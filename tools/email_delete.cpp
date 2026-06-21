#include <iostream>
#include <fstream>
#include <string>
#include <curl/curl.h>

// Reads access_token from a simple text file (one line)
static std::string read_token(const std::string& path) {
    std::ifstream f(path);
    std::string token;
    std::getline(f, token);
    return token;
}

static size_t write_cb(char* ptr, size_t size, size_t nmemb, std::string* out) {
    out->append(ptr, size * nmemb);
    return size * nmemb;
}

static std::string gmail_get(const std::string& token, const std::string& url) {
    CURL* curl = curl_easy_init();
    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());

    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

static std::string gmail_delete(const std::string& token, const std::string& msg_id) {
    CURL* curl = curl_easy_init();
    std::string response;
    struct curl_slist* headers = nullptr;
    headers = curl_slist_append(headers, ("Authorization: Bearer " + token).c_str());

    std::string url = "https://gmail.googleapis.com/gmail/v1/users/me/messages/" + msg_id + "/trash";
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, 0L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);
    curl_easy_perform(curl);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return response;
}

int main() {
    // Token file: one line containing the raw Bearer token
    std::string token = read_token("/tmp/gmail_token.txt");
    if (token.empty()) {
        std::cerr << "Error: /tmp/gmail_token.txt is empty or missing\n";
        return 1;
    }

    std::cout << "[1/3] Searching for test email...\n";
    std::string search_url =
        "https://gmail.googleapis.com/gmail/v1/users/me/messages"
        "?q=subject%3A%22AI+Guardian+Test%22&maxResults=1";
    std::string result = gmail_get(token, search_url);
    std::cout << "Search result: " << result << "\n";

    // Naive parse: find "id":  in JSON
    std::string id_key = "\"id\":\"";
    size_t pos = result.find(id_key);
    if (pos == std::string::npos) {
        std::cerr << "No test email found.\n";
        return 1;
    }
    pos += id_key.size();
    size_t end = result.find('"', pos);
    std::string msg_id = result.substr(pos, end - pos);
    std::cout << "[2/3] Found message ID: " << msg_id << "\n";

    std::cout << "[3/3] Moving to Trash (Gmail REST API /trash)...\n";
    std::string del_result = gmail_delete(token, msg_id);
    std::cout << "Result: " << del_result << "\n";

    std::cout << "Done.\n";
    return 0;
}
