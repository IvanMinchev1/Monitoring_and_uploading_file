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

static std::string g_historyLogFile;
static std::mutex g_historyLogMutex;

static void AppendToHistoryLog(const std::string& message)
{
    std::lock_guard<std::mutex> lock(g_historyLogMutex);

    using namespace std::chrono;
    auto now = system_clock::to_time_t(system_clock::now());
    std::tm localTime{};
    localtime_r(&now, &localTime);

    std::ostringstream stamp;
    stamp << std::put_time(&localTime, "%Y-%m-%d %H:%M:%S") << " [HIST] ";

    std::ofstream ofs(g_historyLogFile, std::ios::app);
    if (ofs.is_open()) {
        ofs << stamp.str() << message << "\n";
    }
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
    std::string* str = reinterpret_cast<std::string*>(userdata);
    str->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

struct CurlResult {
    long httpCode;
    std::string responseBody;
    bool success;
};

static CurlResult PerformCurlRequest(CURL* curl, const std::string& requestDesc)
{
    AppendToHistoryLog("REQUEST => " + requestDesc);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);

    CurlResult result;
    result.httpCode = 0;
    result.responseBody = "";
    result.success = false;

    if (res != CURLE_OK) {

        std::string failMsg = "REQUEST FAILED => " + std::string(curl_easy_strerror(res));
        logMessage(LogLevel::ERROR, failMsg);
        AppendToHistoryLog(failMsg);
        return result;
    }

    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

    {
        std::ostringstream respMsg;
        respMsg << "RESPONSE CODE => " << code << "\n";
        respMsg << "RESPONSE BODY => " << response;
        AppendToHistoryLog(respMsg.str());
    }

    result.httpCode = code;
    result.responseBody = response;
    result.success = (code >= 200 && code < 300);
    return result;
}

static std::string ComputeSHA256Hex(const std::string& filePath)
{
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) {
        logMessage(LogLevel::ERROR, "Cannot open file for hashing: " + filePath);
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
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << (int)hash[i];
    }
    return oss.str();
}

bool GetMoveItAuthToken_UserPassword(const std::string& username, const std::string& password, bool /*logRequests*/)
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed to init cURL in GetMoveItAuthToken_UserPassword.");
        return false;
    }

    std::string url = g_moveitServer + "/api/v1/auth/token";
    std::string postFields = "grant_type=password&username=" + username + "&password=" + password;
    std::string requestDesc = "POST " + url + " (Auth ROPC), fields=" + postFields;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

    auto res = PerformCurlRequest(curl, requestDesc);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!res.success) {
        logMessage(LogLevel::ERROR, "Auth request not successful. HTTP code=" + std::to_string(res.httpCode));
        return false;
    }

    std::string key = "\"access_token\":\"";
    auto pos = res.responseBody.find(key);
    if (pos != std::string::npos) {
        pos += key.size();
        auto endPos = res.responseBody.find("\"", pos);
        if (endPos != std::string::npos) {
            g_accessToken = res.responseBody.substr(pos, endPos - pos);
        }
    }

    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "Failed parse accessToken from response. ");
        AppendToHistoryLog("PARSED param => accessToken= (empty!)");
        return false;
    }

    {
        std::ostringstream paramMsg;
        paramMsg << "PARSED param => accessToken= " << g_accessToken.substr(0, 8) << "...(hidden)";
        AppendToHistoryLog(paramMsg.str());
    }

    logMessage(LogLevel::INFO, "Authenticated => got token (redacted).");
    return true;
}

bool GetFolderIdFromSelf(bool /*logRequests*/)
{
    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "No token, cannot get folderId.");
        return false;
    }

    std::string url = g_moveitServer + "/api/v1/users/self";
    std::string requestDesc = "GET " + url + " (get user info)";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed cURL init in GetFolderIdFromSelf.");
        return false;
    }

    struct curl_slist* headers = nullptr;
    std::string authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    auto res = PerformCurlRequest(curl, requestDesc);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!res.success) {
        logMessage(LogLevel::ERROR, "GetFolderIdFromSelf not successful. code=" + std::to_string(res.httpCode));
        return false;
    }

    std::string key = "\"homeFolderID\":";
    auto pos = res.responseBody.find(key);
    if (pos == std::string::npos) {
        logMessage(LogLevel::ERROR, "No 'homeFolderID' found in user info. ");
        return false;
    }
    pos += key.size();
    while (pos < res.responseBody.size() && isspace((unsigned char)res.responseBody[pos])) pos++;
    if (pos < res.responseBody.size() && res.responseBody[pos]=='"') pos++;

    std::string idStr;
    while (pos < res.responseBody.size()) {
        char c = res.responseBody[pos];
        if ((c>='0' && c<='9') || c=='-') {
            idStr.push_back(c);
        } else {
            break;
        }
        pos++;
    }

    if (idStr.empty()) {
        logMessage(LogLevel::ERROR, "Parsing homeFolderID => empty. ");
        return false;
    }
    g_folderId = idStr;

    {
        std::ostringstream paramMsg;
        paramMsg << "PARSED param => folderId= " << g_folderId;
        AppendToHistoryLog(paramMsg.str());
    }
    logMessage(LogLevel::INFO, "homeFolderID=" + g_folderId);
    return true;
}

bool DeleteFileById(const std::string& fileId)
{
    if (fileId.empty()) return false;

    std::string url = g_moveitServer + "/api/v1/files/" + fileId;
    std::string requestDesc = "DELETE " + url + " (delete old file by ID=" + fileId + ")";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed cURL in DeleteFileById.");
        return false;
    }

    struct curl_slist* headers = nullptr;
    auto authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "DELETE");

    auto res = PerformCurlRequest(curl, requestDesc);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!res.success) {
        logMessage(LogLevel::ERROR, "Delete file fail => code=" + std::to_string(res.httpCode));
        return false;
    }

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
    std::string requestDesc = "POST " + url + " (upload new file). fileHash=" + fileHash;

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
    curl_mime_data(part, "Uploaded partial-write safe (ID-based)", CURL_ZERO_TERMINATED);

    struct curl_slist* headers=nullptr;
    auto authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    auto res = PerformCurlRequest(curl, requestDesc);

    curl_mime_free(form);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (!res.success) {
        logMessage(LogLevel::ERROR, "Upload fail => code=" + std::to_string(res.httpCode));
        return "";
    }

    std::string newId;
    std::string idKey="\"id\":\"";
    auto p= res.responseBody.find(idKey);
    if (p!=std::string::npos) {
        p+=idKey.size();
        auto e= res.responseBody.find("\"", p);
        if (e!=std::string::npos) {
            newId= res.responseBody.substr(p, e-p);
        }
    }

    if (!newId.empty()) {
        logMessage(LogLevel::INFO, "Uploaded => new ID=" + newId);
        {
            std::ostringstream paramMsg;
            paramMsg << "PARSED param => newFileId=" << newId;
            AppendToHistoryLog(paramMsg.str());
        }
    } else {
        logMessage(LogLevel::WARN, "Upload success but can't parse 'id': " + res.responseBody);
    }

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
                auto& track= it->second;
                if (!track.needsUpload) {
                    ++it;
                    continue;
                }
                auto diff= now- track.lastEvent;
                if (std::chrono::duration_cast<std::chrono::seconds>(diff).count()>= STABILITY_SECONDS) {
                    bool fileOK=true;
                    uintmax_t curSize=0;
                    try {
                        curSize= fs::file_size(it->first);
                    } catch(...) {
                        fileOK=false;
                    }
                    if (fileOK && curSize== track.lastSize) {
                        StableFile sf;
                        sf.path= it->first;
                        sf.eventType= track.eventType;
                        sf.oldFileId= track.remoteFileId;
                        stableList.push_back(sf);

                        it= g_fileMap.erase(it);
                        continue;
                    } else {
                        track.lastSize=curSize;
                        track.lastEvent= now;
                    }
                }
                ++it;
            }
        }

        for (auto& sf: stableList) {
            if (sf.eventType==LocalEventType::Created) {
                auto newId= UploadFile_GetNewId(sf.path);
                if (!newId.empty()) {
                    FileTrack ft;
                    ft.eventType= LocalEventType::Created;
                    ft.lastEvent= std::chrono::steady_clock::now();
                    ft.lastSize= 0;
                    ft.needsUpload= false;
                    ft.remoteFileId= newId;

                    std::lock_guard<std::mutex> lock(g_fileMapMutex);
                    g_fileMap[sf.path]= ft;
                }
            } else {
                if (!sf.oldFileId.empty()) {
                    logMessage(LogLevel::INFO, "Modified => deleting old ID=" + sf.oldFileId);
                    if(!DeleteFileById(sf.oldFileId)) {
                        logMessage(LogLevel::WARN, "delete old ID failed => continuing...");
                    }
                }
                auto newId= UploadFile_GetNewId(sf.path);
                if (!newId.empty()) {
                    FileTrack ft;
                    ft.eventType= LocalEventType::Modified;
                    ft.lastEvent= std::chrono::steady_clock::now();
                    ft.lastSize= 0;
                    ft.needsUpload= false;
                    ft.remoteFileId= newId;

                    std::lock_guard<std::mutex> lock(g_fileMapMutex);
                    g_fileMap[sf.path]= ft;
                }
            }
        }
    }
}
static void fileSystemEventCallback(
    ConstFSEventStreamRef /*ref*/,
    void* /*ctx*/,
    size_t numEvents,
    void* eventPaths,
    const FSEventStreamEventFlags flags[],
    const FSEventStreamEventId /*ids*/[])
{
    char** paths = (char**)eventPaths;

    for (size_t i=0; i<numEvents; i++){
        std::string localPath= paths[i];

        
        if (localPath == g_historyLogFile) {
            // do nothing
            continue;
        }

        bool isCreated  = (flags[i] & kFSEventStreamEventFlagItemCreated)!=0;
        bool isModified = (flags[i] & kFSEventStreamEventFlagItemModified)!=0;
        if(!isCreated && !isModified) {
            // only care about create/modify
            continue;
        }

        logMessage(LogLevel::INFO, (isCreated?"CREATED ":"MODIFIED ") + localPath);

        uintmax_t sz=0;
        try {
            sz= fs::file_size(localPath);
        } catch(...) {
            logMessage(LogLevel::ERROR, "fs::file_size fail => continue.");
            continue;
        }

        auto now= std::chrono::steady_clock::now();
        auto eType= isCreated? LocalEventType::Created : LocalEventType::Modified;

        std::lock_guard<std::mutex> lock(g_fileMapMutex);
        auto it= g_fileMap.find(localPath);
        if(it== g_fileMap.end()) {
            
            FileTrack ft;
            ft.eventType= eType;
            ft.lastEvent= now;
            ft.lastSize= sz;
            ft.needsUpload= true;
            ft.remoteFileId="";
            g_fileMap[localPath]= ft;
        } else {
            auto& track= it->second;
            if (track.eventType==LocalEventType::Created && eType==LocalEventType::Modified) {
                track.eventType= LocalEventType::Modified;
            }
            track.lastEvent= now;
            track.lastSize= sz;
            track.needsUpload= true;
        }
    }
}

int main(int argc, char* argv[])
{
    if(argc<5) {
        std::cerr<<"Usage: "<<argv[0]<<" <MOVEitServerURL> <username> <password> <localFolderPath>\n";
        return 1;
    }

    g_moveitServer= argv[1];
    std::string user= argv[2];
    std::string pass= argv[3];
    std::string watchDir= argv[4];

    g_historyLogFile= watchDir + "/history_log.txt";

    curl_global_init(CURL_GLOBAL_DEFAULT);

    if(!GetMoveItAuthToken_UserPassword(user, pass, true)) {
        logMessage(LogLevel::ERROR, "Auth fail => exit.");
        curl_global_cleanup();
        return 1;
    }

    if(!GetFolderIdFromSelf(true)) {
        logMessage(LogLevel::ERROR, "No folderId => exit.");
        curl_global_cleanup();
        return 1;
    }

    CFStringRef cfPath= CFStringCreateWithCString(kCFAllocatorDefault,
                                                 watchDir.c_str(),
                                                 kCFStringEncodingUTF8);
    CFArrayRef paths= CFArrayCreate(kCFAllocatorDefault,
                                    (const void**)&cfPath,
                                    1,
                                    nullptr);

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

    if(!stream) {
        logMessage(LogLevel::ERROR, "FSEventStreamCreate fail => exit.");
        CFRelease(cfPath);
        CFRelease(paths);
        curl_global_cleanup();
        return 1;
    }

    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    if(!FSEventStreamStart(stream)) {
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

    logMessage(LogLevel::INFO, "Watching directory: " + watchDir);
    {
        std::ostringstream msg;
        msg<<"History log file: "<<g_historyLogFile;
        logMessage(LogLevel::INFO, msg.str());
        AppendToHistoryLog("PROGRAM START => watching " + watchDir);
    }
    logMessage(LogLevel::INFO, "Handle partial writes (3s). Created => upload. Modified => delete old ID => upload.");
    logMessage(LogLevel::INFO, "Press Ctrl+C to exit.");

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

    AppendToHistoryLog("PROGRAM END => cleaning up.");
    curl_global_cleanup();
    return 0;
}
