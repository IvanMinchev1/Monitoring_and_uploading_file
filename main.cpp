#include <CoreServices/CoreServices.h>
#include <curl/curl.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <ctime>
#include <fstream>
#include <CommonCrypto/CommonCrypto.h> 

enum class LogLevel {
    INFO,
    WARN,
    ERROR
};

static void logMessage(LogLevel level, const std::string& msg)
{
    auto now = std::time(nullptr);
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


static size_t WriteCallback(void* ptr, size_t size, size_t nmemb, void* userdata)
{
    std::string* str = static_cast<std::string*>(userdata);
    str->append(static_cast<char*>(ptr), size * nmemb);
    return size * nmemb;
}

bool GetMoveItAuthToken_UserPassword(const std::string& username,
                                     const std::string& password)
{
    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed to init cURL in GetMoveItAuthToken_UserPassword.");
        return false;
    }

    std::string url        = g_moveitServer + "/api/v1/auth/token";
    std::string postFields = "grant_type=password&username=" + username + "&password=" + password;

    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, "Content-Type: application/x-www-form-urlencoded");
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postFields.c_str());

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "Auth request failed: " + std::string(curl_easy_strerror(res)));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long httpCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        logMessage(LogLevel::ERROR, "Auth request got HTTP code: " + std::to_string(httpCode));
        logMessage(LogLevel::ERROR, "Response: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }
    std::string tokenKey = "\"access_token\":\"";
    auto pos = response.find(tokenKey);
    if (pos != std::string::npos) {
        pos += tokenKey.size();
        auto endPos = response.find("\"", pos);
        if (endPos != std::string::npos) {
            g_accessToken = response.substr(pos, endPos - pos);
        }
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "Failed to parse access token: " + response);
        return false;
    }

    logMessage(LogLevel::INFO, "Successfully obtained MOVEit access token.");
    return true;
}

bool GetFolderIdFromSelf()
{
    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "No token. Cannot retrieve folderId.");
        return false;
    }

    std::string url = g_moveitServer + "/api/v1/users/self";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed to init cURL in GetFolderIdFromSelf.");
        return false;
    }

    struct curl_slist* headers = nullptr;
    std::string authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "GetFolderIdFromSelf failed: " + std::string(curl_easy_strerror(res)));
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long httpCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        logMessage(LogLevel::ERROR, "/users/self returned HTTP " + std::to_string(httpCode));
        logMessage(LogLevel::ERROR, "Response: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    const std::string key = "\"homeFolderID\":";
    auto pos = response.find(key);
    if (pos == std::string::npos) {
        logMessage(LogLevel::ERROR, "Failed to find 'homeFolderID' in response: " + response);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    pos += key.size();
    while (pos < response.size() && isspace(static_cast<unsigned char>(response[pos]))) {
        pos++;
    }

    if (pos < response.size() && response[pos] == '"') {
        pos++;
    }

    std::string idStr;
    while (pos < response.size()) {
        char c = response[pos];
        if ((c >= '0' && c <= '9') || c == '-') {
            idStr.push_back(c);
        } else {
            break;
        }
        pos++;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    if (idStr.empty()) {
        logMessage(LogLevel::ERROR, "No numeric folderId found in /users/self: " + response);
        return false;
    }

    g_folderId = idStr;
    logMessage(LogLevel::INFO, "Discovered folderId (homeFolderID) = " + g_folderId);
    return true;
}

static std::string ComputeSHA256Hex(const std::string& filePath)
{
    std::ifstream ifs(filePath, std::ios::binary);
    if (!ifs.is_open()) {
        logMessage(LogLevel::ERROR, "ComputeSHA256Hex: cannot open file: " + filePath);
        return "";
    }

    CC_SHA256_CTX ctx;
    CC_SHA256_Init(&ctx);

    const size_t bufSize = 8192;
    char buffer[bufSize];
    while (ifs.good()) {
        ifs.read(buffer, bufSize);
        std::streamsize bytesRead = ifs.gcount();
        if (bytesRead > 0) {
            CC_SHA256_Update(&ctx, buffer, static_cast<CC_LONG>(bytesRead));
        }
    }
    ifs.close();

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256_Final(hash, &ctx);

    std::ostringstream oss;
    for (int i = 0; i < CC_SHA256_DIGEST_LENGTH; i++) {
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(hash[i]);
    }
    return oss.str();
}

bool UploadFileToFolder(const std::string& localFilePath)
{
    if (g_accessToken.empty()) {
        logMessage(LogLevel::ERROR, "No token. Cannot upload.");
        return false;
    }
    if (g_folderId.empty()) {
        logMessage(LogLevel::ERROR, "No folderId. Cannot upload.");
        return false;
    }

    std::string fileHash = ComputeSHA256Hex(localFilePath);
    if (fileHash.empty()) {
        logMessage(LogLevel::ERROR, "Skipping upload because file hashing failed.");
        return false;
    }

    std::string url = g_moveitServer + "/api/v1/folders/" + g_folderId + "/files";

    CURL* curl = curl_easy_init();
    if (!curl) {
        logMessage(LogLevel::ERROR, "Failed to init cURL in UploadFileToFolder.");
        return false;
    }
    curl_mime* form = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(form);
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
    curl_mime_data(part, "Uploaded by C++ code", CURL_ZERO_TERMINATED);

    struct curl_slist* headers = nullptr;
    std::string authHeader = "Authorization: Bearer " + g_accessToken;
    headers = curl_slist_append(headers, authHeader.c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, form);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

    std::string response;
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        logMessage(LogLevel::ERROR, "Upload request failed: " + std::string(curl_easy_strerror(res)));
        curl_mime_free(form);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    long httpCode;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &httpCode);
    if (httpCode < 200 || httpCode >= 300) {
        logMessage(LogLevel::ERROR, "Upload got HTTP code: " + std::to_string(httpCode));
        logMessage(LogLevel::ERROR, "Response: " + response);
        curl_mime_free(form);
        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        return false;
    }

    // Cleanup
    curl_mime_free(form);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    logMessage(LogLevel::INFO, "Uploaded file successfully to folder " + g_folderId + ": " + localFilePath);
    return true;
}

static void fileSystemEventCallback(
    ConstFSEventStreamRef /*streamRef*/,
    void* /*clientCallBackInfo*/,
    size_t numEvents,
    void* eventPaths,
    const FSEventStreamEventFlags eventFlags[],
    const FSEventStreamEventId /*eventIds*/[])
{
    char** paths = static_cast<char**>(eventPaths);

    for (size_t i = 0; i < numEvents; ++i) {
        std::string changedPath = paths[i];
        FSEventStreamEventFlags flags = eventFlags[i];

        logMessage(LogLevel::INFO, "FSEvents: Detected change at path: " + changedPath);

        if (flags & kFSEventStreamEventFlagItemCreated) {
            if (!UploadFileToFolder(changedPath)) {
                logMessage(LogLevel::ERROR, "Failed to upload: " + changedPath);
            }
        }
    }
}


int main(int argc, char* argv[])
{
    if (argc < 5) {
        std::cerr << "Usage: " << argv[0]
                  << " <MOVEitServerURL> <username> <password> <localFolderPath>\n";
        return 1;
    }

    g_moveitServer  = argv[1];
    std::string user = argv[2];
    std::string pass = argv[3];
    std::string watchDir = argv[4];

    
    curl_global_init(CURL_GLOBAL_DEFAULT);

    
    if (!GetMoveItAuthToken_UserPassword(user, pass)) {
        logMessage(LogLevel::ERROR, "Authentication failed. Exiting.");
        curl_global_cleanup();
        return 1;
    }

    
    if (!GetFolderIdFromSelf()) {
        logMessage(LogLevel::ERROR, "Cannot proceed without folderId. Exiting.");
        curl_global_cleanup();
        return 1;
    }

    
    CFStringRef cfPath = CFStringCreateWithCString(
        kCFAllocatorDefault,
        watchDir.c_str(),
        kCFStringEncodingUTF8
    );
    CFArrayRef pathsToWatch = CFArrayCreate(
        kCFAllocatorDefault,
        reinterpret_cast<const void**>(&cfPath),
        1,
        nullptr
    );

    FSEventStreamContext context = {0, nullptr, nullptr, nullptr, nullptr};
    FSEventStreamRef stream = FSEventStreamCreate(
        kCFAllocatorDefault,
        &fileSystemEventCallback,
        &context,
        pathsToWatch,
        kFSEventStreamEventIdSinceNow,
        1.0,
        kFSEventStreamCreateFlagFileEvents
    );

    if (!stream) {
        logMessage(LogLevel::ERROR, "Failed to create FSEventStream. Exiting.");
        CFRelease(cfPath);
        CFRelease(pathsToWatch);
        curl_global_cleanup();
        return 1;
    }

    FSEventStreamScheduleWithRunLoop(stream, CFRunLoopGetCurrent(), kCFRunLoopDefaultMode);
    if (!FSEventStreamStart(stream)) {
        logMessage(LogLevel::ERROR, "Failed to start FSEventStream. Exiting.");
        FSEventStreamRelease(stream);
        CFRelease(cfPath);
        CFRelease(pathsToWatch);
        curl_global_cleanup();
        return 1;
    }

    
    CFRelease(cfPath);
    CFRelease(pathsToWatch);

    logMessage(LogLevel::INFO, "Watching folder: " + watchDir);
    logMessage(LogLevel::INFO, "Folder ID: " + g_folderId);
    logMessage(LogLevel::INFO, "New files => POST /api/v1/folders/" + g_folderId + "/files");
    logMessage(LogLevel::INFO, "Press Ctrl+C to exit...");

    
    CFRunLoopRun();

    
    logMessage(LogLevel::WARN, "Exiting run loop.");
    FSEventStreamStop(stream);
    FSEventStreamInvalidate(stream);
    FSEventStreamRelease(stream);

    curl_global_cleanup();
    return 0;
}
