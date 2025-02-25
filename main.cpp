#include <CoreServices/CoreServices.h>
#include <curl/curl.h>
#include <CommonCrypto/CommonCrypto.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <mutex>
#include <string>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <chrono>

namespace fs = std::filesystem;

enum class LogLevel {
    INFO,
    WARN,
    ERROR
};

static void logMessage(LogLevel level, const std::string& msg)
{
    using namespace std::chrono;
    auto now = system_clock::to_time_t(system_clock::now());
    std::tm localTime{};
    localtime_r(&now, &localTime);

    std::ostringstream oss;
    oss << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S") << " ";

    switch (level) {
        case LogLevel::INFO:  oss << "[INFO]  ";  break;
        case LogLevel::WARN:  oss << "[WARN]  ";  break;
        case LogLevel::ERROR: oss << "[ERROR] "; break;
    }

    oss << msg;
    std::cout << oss.str() << std::endl;
}

static std::string g_moveitServer;
static std::string g_accessToken;
static std::string g_folderId;

enum class LocalEventType {
    Created,
    Modified
};

struct FileTrack {
    LocalEventType eventType;
    std::chrono::steady_clock::time_point lastEvent;
    uintmax_t lastSize;
    bool needsUpload;
    std::string remoteFileId;
};

static std::unordered_map<std::string, FileTrack> g_fileMap;
static std::mutex g_fileMapMutex;
static bool g_stopWorker = false;
static std::thread g_workerThread;


static size_t WriteCallback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string* str = static_cast<std::string*>(userdata);
    str->append((char*)ptr, size * nmemb);
    return size * nmemb;
}


bool GetMoveItAuthToken_UserPassword(const std::string& username, const std::string& password)
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed cURL init for auth.");
        return false;
    }

    std::string url = g_moveitServer + "/api/v1/auth/token";
    std::string postFields = "grant_type=password&username=" + username + "&password=" + password;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "Auth request failed: " + std::string(curl_easy_strerror(res)));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long httpCode = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        logMessage(LogLevel::ERROR, "Auth HTTP code: " + std::to_string(httpCode));
        logMessage(LogLevel::ERROR, "Resp: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    
    std::string key = "\"access_token\":\"";
    auto pos = response.find(key);
    if (pos != std::string::npos) {
        pos += key.size();
        auto endPos = response.find("\"", pos);
        if (endPos != std::string::npos) {
            g_accessToken = response.substr(pos, endPos - pos);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "Cannot parse access token from: " + response);
        return false;
    }

    logMessage(LogLevel::INFO, "Authenticated => got token.");
    return true;
}


bool GetFolderIdFromSelf()
{
    if (g_accessToken.empty()) return false;

    
    std::string url = g_moveitServer + "/api/v1/users/self";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed cURL in GetFolderIdFromSelf.");
        return false;
    }

    struct curl_slist* headers = nullptr;
    auto authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "GetFolderIdFromSelf failed: " + std::string(curl_easy_strerror(res)));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code < 200 || code >= 300) {
        logMessage(LogLevel::ERROR, "/users/self code: " + std::to_string(code));
        logMessage(LogLevel::ERROR, "Resp: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    std::string key = "\"homeFolderID\":";
    auto pos = response.find(key);
    if (pos == std::string::npos) {
        logMessage(LogLevel::ERROR, "No homeFolderID in: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    pos += key.size();
    while (pos < response.size() && isspace((unsigned char)response[pos])) pos++;
    if (pos < response.size() && response[pos] == '"') pos++;

    std::string idStr;
    while (pos < response.size()) {
        char c = response[pos];
        if ((c >= '0' && c <= '9') || c=='-') {
            idStr.push_back(c);
        } else {
            break;
        }
        pos++;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (idStr.empty()) {
        logMessage(LogLevel::ERROR, "Failed parse folderId from: " + response);
        return false;
    }
    
    g_folderId = idStr;
    logMessage(LogLevel::INFO, "Got folderId=" + g_folderId);
    return true;
}


static std::string ComputeSHA256Hex(const std::string& filePath)
{
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) {
        logMessage(LogLevel::ERROR, "Cannot open for hashing: " + filePath);
        return "";
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    const size_t bufSize = 8192;
    char buffer[bufSize];
    while (ifs.good()) {
        ifs.read(buffer, bufSize);
        auto bytesRead = ifs.gcount();
        if (bytesRead > 0) {
            CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytesRead);
        }
    }
    ifs.close();

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (int i=0; i<CC_SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)hash[i];
    }
    return oss.str();
}


bool DeleteFileById(const std::string& fileId)
{
    if (fileId.empty()) {
        return false;
    }
    std::string url = g_moveitServer + "/api/v1/files/" + fileId;

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "cURL init fail in DeleteFileById.");
        return false;
    }

    struct curl_slist* headers = nullptr;
    auto authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    auto res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "Delete request fail: " + std::string(curl_easy_strerror(res)));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long code=0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code<200 || code>=300) {
        logMessage(LogLevel::ERROR, "Delete code=" + std::to_string(code));
        logMessage(LogLevel::ERROR, "Resp: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    logMessage(LogLevel::INFO, "Deleted file ID=" + fileId);
    return true;
}


std::string UploadFile_GetNewId(const std::string& localFilePath)
{
    if (g_accessToken.empty()||g_folderId.empty()) return "";

    std::string fileHash = ComputeSHA256Hex(localFilePath);
    if (fileHash.empty()) {
        return "";
    }
    std::string url = g_moveitServer + "/api/v1/folders/" + g_folderId + "/files";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed cURL in UploadFile_GetNewId.");
        return "";
    }

    curl_mime* form = curl_mime_init(curl);


    auto part = curl_mime_addpart(form);
    curl_mime_name(part, "hashtype");
    curl_mime_data(part, "sha-256", CURL_ZERO_TERMINATED);

    
    part = curl_mime_addpart(form);
    curl_mime_name(part, "hash");
    curl_mime_data(part, fileHash.c_str(), CURL_ZERO_TERMINATED);


    part = curl_mime_addpart(form);
    curl_mime_name(part, "file");
    curl_mime_filedata(part, localFilePath.c_str());

    
    part = curl_mime_addpart(form);
    curl_mime_name(part, "comments");
    curl_mime_data(part, "Partial-write safe + ID-based delete", CURL_ZERO_TERMINATED);

    struct curl_slist* headers=nullptr;
    auto authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    auto res2 = curl_easy_perform(curl);
    if (res2 != CURLE_OK) {
        logMessage(LogLevel::ERROR, "Upload fail: " + std::string(curl_easy_strerror(res2)));
        curl_mime_free(form);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return "";
    }

    long code=0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code<200 || code>=300) {
        logMessage(LogLevel::ERROR, "Upload code=" + std::to_string(code));
        logMessage(LogLevel::ERROR, "Resp: " + response);
        curl_mime_free(form);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return "";
    }

    
    std::string newId;
    std::string idKey="\"id\":\"";
    auto p = response.find(idKey);
    if (p!=std::string::npos) {
        p+=idKey.size();
        auto e = response.find("\"", p);
        if (e!=std::string::npos) {
            newId= response.substr(p, e-p);
        }
    }
    if (!newId.empty()) {
        logMessage(LogLevel::INFO, "Uploaded => new ID=" + newId);
    } else {
        logMessage(LogLevel::WARN, "Upload success but can't parse 'id': " + response);
    }

    
    curl_mime_free(form);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    return newId;
}


struct StableFile {
    std::string path;
    LocalEventType eventType;
    std::string oldFileId; 
};

static void UploadStableFilesWorker()
{
    const int STABILITY_SECONDS=3;

    while(!g_stopWorker) {
        std::this_thread::sleep_for(std::chrono::seconds(1));

        std::vector<StableFile> stableList;

        {
            std::lock_guard<std::mutex> lock(g_fileMapMutex);
            auto now=std::chrono::steady_clock::now();

            for (auto it=g_fileMap.begin(); it!=g_fileMap.end();) {
                auto& ft=it->second;
                if (!ft.needsUpload) {
                    ++it;
                    continue;
                }

                auto diff = now - ft.lastEvent;
                if (std::chrono::duration_cast<std::chrono::seconds>(diff).count() >= STABILITY_SECONDS) {
                    
                    bool fileOk=true;
                    uintmax_t curSize=0;
                    try{
                        curSize=fs::file_size(it->first);
                    } catch(...){
                        fileOk=false;
                    }
                    if (fileOk && curSize==ft.lastSize) {
                        
                        StableFile sf;
                        sf.path = it->first;
                        sf.eventType = ft.eventType;
                        sf.oldFileId = ft.remoteFileId;
                        stableList.push_back(sf);

                        it=g_fileMap.erase(it);
                        continue;
                    } else {
                        
                        ft.lastSize=curSize;
                        ft.lastEvent=now;
                    }
                }
                ++it;
            }
        }

        
        for (auto& sf: stableList) {
            if (sf.eventType==LocalEventType::Created) {
                
                auto newId= UploadFile_GetNewId(sf.path);
                if (!newId.empty()) {
                    FileTrack track;
                    track.eventType=LocalEventType::Created;
                    track.lastEvent=std::chrono::steady_clock::now();
                    track.lastSize=0;
                    track.needsUpload=false;
                    track.remoteFileId=newId;

                    std::lock_guard<std::mutex> lock(g_fileMapMutex);
                    g_fileMap[sf.path]=track;
                }
            } else {
                
                if (!sf.oldFileId.empty()) {
                    logMessage(LogLevel::INFO, "Modified => Deleting old file ID=" + sf.oldFileId);
                    if (!DeleteFileById(sf.oldFileId)) {
                        logMessage(LogLevel::WARN, "Delete old file ID failed, continue upload...");
                    }
                }
                
                auto newId= UploadFile_GetNewId(sf.path);
                if (!newId.empty()) {
                    FileTrack track;
                    track.eventType=LocalEventType::Modified;
                    track.lastEvent=std::chrono::steady_clock::now();
                    track.lastSize=0;
                    track.needsUpload=false;
                    track.remoteFileId=newId;

                    std::lock_guard<std::mutex> lock(g_fileMapMutex);
                    g_fileMap[sf.path]=track;
                }
            }
        }
    }
}


static void fileSystemEventCallback(
    ConstFSEventStreamRef,
    void* ,
    size_t numEvents,
    void* eventPaths,
    const FSEventStreamEventFlags flags[],
    const FSEventStreamEventId [])
{
    char** paths = (char**)eventPaths;

    for (size_t i=0; i<numEvents; i++){
        std::string localPath= paths[i];
        bool isCreated  = (flags[i] & kFSEventStreamEventFlagItemCreated)!=0;
        bool isModified = (flags[i] & kFSEventStreamEventFlagItemModified)!=0;

        if (!isCreated && !isModified) {
            continue;
        }
        auto eType = isCreated ? LocalEventType::Created : LocalEventType::Modified;

        logMessage(LogLevel::INFO, (isCreated ? "CREATED " : "MODIFIED ") + localPath);

        uintmax_t sz=0;
        try {
            sz= fs::file_size(localPath);
        } catch(...) {
            
        }

        auto now= std::chrono::steady_clock::now();

        std::lock_guard<std::mutex> lock(g_fileMapMutex);

        auto it=g_fileMap.find(localPath);
        if (it==g_fileMap.end()) {
            FileTrack ft;
            ft.eventType=eType;
            ft.lastEvent=now;
            ft.lastSize=sz;
            ft.needsUpload=true;
            ft.remoteFileId=""; 
            g_fileMap[localPath]=ft;
        } else {
            auto& ft= it->second;
            
            if (ft.eventType==LocalEventType::Created && eType==LocalEventType::Modified) {
                ft.eventType=LocalEventType::Modified;
            }
            ft.lastEvent= now;
            ft.lastSize= sz;
            ft.needsUpload=true;
            
        }
    }
}


int main(int argc, char* argv[])
{
    if (argc<5) {
        std::cerr<<"Usage: "<<argv[0]<<" <MOVEitServerURL> <username> <password> <localFolderPath>\n";
        return 1;
    }

    g_moveitServer= argv[1];
    std::string user= argv[2];
    std::string pass= argv[3];
    std::string watchDir= argv[4];

    curl_global_init(CURL_GLOBAL_DEFAULT);

   
    if (!GetMoveItAuthToken_UserPassword(user, pass)) {
        logMessage(LogLevel::ERROR, "Auth fail => exit.");
        curl_global_cleanup();
        return 1;
    }

    
    if (!GetFolderIdFromSelf()) {
        logMessage(LogLevel::ERROR, "No folderId => exit.");
        curl_global_cleanup();
        return 1;
    }

    CFStringRef cfPath= CFStringCreateWithCString(
        kCFAllocatorDefault,
        watchDir.c_str(),
        kCFStringEncodingUTF8
    );
    CFArrayRef paths= CFArrayCreate(
        kCFAllocatorDefault,
        (const void**)&cfPath,
        1,
        nullptr
    );

    FSEventStreamContext ctx= {0, nullptr, nullptr, nullptr, nullptr};
    FSEventStreamRef stream= FSEventStreamCreate(
        kCFAllocatorDefault,
        &fileSystemEventCallback,
        &ctx,
        paths,
        kFSEventStreamEventIdSinceNow,
        1.0,
        kFSEventStreamCreateFlagFileEvents
    );

    if (!stream) {
        logMessage(LogLevel::ERROR, "FSEventStreamCreate fail => exit.");
        CFRelease(cfPath);
        CFRelease(paths);
        curl_global_cleanup();
        return 1;
    }

    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    if (!FSEventStreamStart(stream)) {
        logMessage(LogLevel::ERROR, "FSEventStreamStart fail => exit.");
        FSEventStreamRelease(stream);
        CFRelease(cfPath);
        CFRelease(paths);
        curl_global_cleanup();
        return 1;
    }


    CFRelease(cfPath);
    CFRelease(paths);

    
    g_workerThread= std::thread(UploadStableFilesWorker);

    logMessage(LogLevel::INFO, "Watching dir: "+watchDir);
    logMessage(LogLevel::INFO, "folderId= "+ g_folderId);
    logMessage(LogLevel::INFO, "Partial write safe => wait 3s. Created => upload; Modified => delete old ID => upload.");

    CFRunLoopRun(); 

    logMessage(LogLevel::WARN, "Exiting CFRunLoop...");
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);

    {
        std::lock_guard<std::mutex> lock(g_fileMapMutex);
        g_stopWorker= true;
    }
    g_workerThread.join();

    curl_global_cleanup();
    return 0;
}
