// Hard Software CXXFastAPI

#ifndef HTTP_LIB_H
#define HTTP_LIB_H

#include <string>
#include <map>
#include <sstream>
#include <vector>
#include <algorithm>
#include <variant>

namespace http {

    class JSON {
    public:
        using Object = std::map<std::string, JSON>;
        using Array = std::vector<JSON>;
        using Value = std::variant<std::nullptr_t, bool, int, double, std::string, Array, Object>;

        JSON() : m_value(nullptr) {}
        JSON(std::nullptr_t) : m_value(nullptr) {}
        JSON(bool value) : m_value(value) {}
        JSON(int value) : m_value(value) {}
        JSON(double value) : m_value(value) {}
        JSON(const char* value) : m_value(std::string(value)) {}
        JSON(const std::string& value) : m_value(value) {}
        JSON(const Array& value) : m_value(value) {}
        JSON(const Object& value) : m_value(value) {}

        static JSON object(std::initializer_list<std::pair<const std::string, JSON>> init) {
            return JSON(Object(init.begin(), init.end()));
        }

        static JSON array(std::initializer_list<JSON> init) {
            return JSON(Array(init.begin(), init.end()));
        }

        static JSON parse(const std::string& json_string) {
            size_t index = 0;
            return parse_value(json_string, index);
        }

        static std::map<std::string, JSON> json_to_map(const JSON& json) {
            if (std::holds_alternative<JSON::Object>(json.get_value())) {
                return std::get<JSON::Object>(json.get_value());
            }
            throw std::runtime_error("JSON value is not an object");
        }

        const Value& get_value() const { return m_value; }

        std::string stringify() const {
            return std::visit([](auto&& arg) -> std::string {
                using T = std::decay_t<decltype(arg)>;
                if constexpr (std::is_same_v<T, std::nullptr_t>) {
                    return "null";
                } else if constexpr (std::is_same_v<T, bool>) {
                    return arg ? "true" : "false";
                } else if constexpr (std::is_same_v<T, int>) {
                    return std::to_string(arg);
                } else if constexpr (std::is_same_v<T, double>) {
                    return std::to_string(arg);
                } else if constexpr (std::is_same_v<T, std::string>) {
                    return "\"" + escape_string(arg) + "\"";
                } else if constexpr (std::is_same_v<T, Array>) {
                    std::string result = "[";
                    for (size_t i = 0; i < arg.size(); ++i) {
                        if (i > 0) result += ",";
                        result += arg[i].stringify();
                    }
                    result += "]";
                    return result;
                } else if constexpr (std::is_same_v<T, Object>) {
                    std::string result = "{";
                    bool first = true;
                    for (const auto& [key, value] : arg) {
                        if (!first) result += ",";
                        result += "\"" + escape_string(key) + "\":" + value.stringify();
                        first = false;
                    }
                    result += "}";
                    return result;
                }
            }, m_value);
        }

        bool is_string() const { return std::holds_alternative<std::string>(m_value); }
        std::string as_string() const {
            if (!is_string()) {
                throw std::runtime_error("JSON value is not a string");
            }
            return std::get<std::string>(m_value);
        }

    private:
        Value m_value;

        static std::string escape_string(const std::string& s) {
            std::string result;
            for (char c : s) {
                switch (c) {
                    case '"': result += "\\\""; break;
                    case '\\': result += "\\\\"; break;
                    case '\b': result += "\\b"; break;
                    case '\f': result += "\\f"; break;
                    case '\n': result += "\\n"; break;
                    case '\r': result += "\\r"; break;
                    case '\t': result += "\\t"; break;
                    default:
                        if ('\x00' <= c && c <= '\x1f') {
                            result += "\\u" + std::string(4 - std::to_string((int)c).length(), '0') + std::to_string((int)c);
                        } else {
                            result += c;
                        }
                }
            }
            return result;
        }

        static JSON parse_value(const std::string& json_string, size_t& index) {
            skip_whitespace(json_string, index);

            if (index >= json_string.length()) {
                throw std::runtime_error("Unexpected end of input");
            }

            char c = json_string[index];
            if (c == '{') {
                return parse_object(json_string, index);
            } else if (c == '[') {
                return parse_array(json_string, index);
            } else if (c == '"') {
                return parse_string(json_string, index);
            } else if (c == 't' || c == 'f') {
                return parse_boolean(json_string, index);
            } else if (c == 'n') {
                return parse_null(json_string, index);
            } else if (c == '-' || (c >= '0' && c <= '9')) {
                return parse_number(json_string, index);
            }

            throw std::runtime_error("Unexpected character");
        }

        static JSON parse_object(const std::string& json_string, size_t& index) {
            Object obj;
            index++;

            while (index < json_string.length()) {
                skip_whitespace(json_string, index);
                if (json_string[index] == '}') {
                    index++;
                    return JSON(obj);
                }

                if (!obj.empty()) {
                    if (json_string[index] != ',') {
                        throw std::runtime_error("Expected ',' in object");
                    }
                    index++;
                    skip_whitespace(json_string, index);
                }

                JSON key_json = parse_string(json_string, index);
                if (!key_json.is_string()) {
                    throw std::runtime_error("Object key must be a string");
                }
                std::string key = key_json.as_string();

                skip_whitespace(json_string, index);

                if (json_string[index] != ':') {
                    throw std::runtime_error("Expected ':' in object");
                }
                index++;

                JSON value = parse_value(json_string, index);
                obj[key] = value;
            }

            throw std::runtime_error("Unterminated object");
        }

        static JSON parse_array(const std::string& json_string, size_t& index) {
            Array arr;
            index++;

            while (index < json_string.length()) {
                skip_whitespace(json_string, index);
                if (json_string[index] == ']') {
                    index++;
                    return JSON(arr);
                }

                if (!arr.empty()) {
                    if (json_string[index] != ',') {
                        throw std::runtime_error("Expected ',' in array");
                    }
                    index++;
                }

                arr.push_back(parse_value(json_string, index));
            }

            throw std::runtime_error("Unterminated array");
        }

        static JSON parse_string(const std::string& json_string, size_t& index) {
            index++;
            std::string result;
            while (index < json_string.length()) {
                char c = json_string[index++];
                if (c == '"') {
                    return JSON(result);
                } else if (c == '\\') {
                    if (index >= json_string.length()) {
                        throw std::runtime_error("Unterminated string");
                    }
                    char next = json_string[index++];
                    switch (next) {
                        case '"': result += '"'; break;
                        case '\\': result += '\\'; break;
                        case '/': result += '/'; break;
                        case 'b': result += '\b'; break;
                        case 'f': result += '\f'; break;
                        case 'n': result += '\n'; break;
                        case 'r': result += '\r'; break;
                        case 't': result += '\t'; break;
                        case 'u': {
                            if (index + 4 > json_string.length()) {
                                throw std::runtime_error("Incomplete Unicode escape");
                            }
                            std::string hex = json_string.substr(index, 4);
                            index += 4;
                            int codepoint = std::stoi(hex, nullptr, 16);
                            result += static_cast<char>(codepoint);
                            break;
                        }
                        default:
                            throw std::runtime_error("Invalid escape sequence");
                    }
                } else {
                    result += c;
                }
            }
            throw std::runtime_error("Unterminated string");
        }

        static JSON parse_boolean(const std::string& json_string, size_t& index) {
            if (json_string.substr(index, 4) == "true") {
                index += 4;
                return JSON(true);
            } else if (json_string.substr(index, 5) == "false") {
                index += 5;
                return JSON(false);
            }
            throw std::runtime_error("Invalid boolean value");
        }

        static JSON parse_null(const std::string& json_string, size_t& index) {
            if (json_string.substr(index, 4) == "null") {
                index += 4;
                return JSON(nullptr);
            }
            throw std::runtime_error("Invalid null value");
        }

        static JSON parse_number(const std::string& json_string, size_t& index) {
            size_t start = index;
            bool is_float = false;
            while (index < json_string.length()) {
                char c = json_string[index];
                if ((c >= '0' && c <= '9') || c == '-' || c == '+' || c == 'e' || c == 'E' || c == '.') {
                    if (c == '.' || c == 'e' || c == 'E') {
                        is_float = true;
                    }
                    index++;
                } else {
                    break;
                }
            }
            std::string num_str = json_string.substr(start, index - start);
            if (is_float) {
                return JSON(std::stod(num_str));
            } else {
                return JSON(std::stoi(num_str));
            }
        }

        static void skip_whitespace(const std::string& json_string, size_t& index) {
            while (index < json_string.length() && std::isspace(json_string[index])) {
                index++;
            }
        }
    };

    enum class Method {
        GET,
        HEAD,
        POST,
        PUT,
        PATCH,
        DELETE,
        CONNECT,
        OPTIONS,
        TRACE,
        UNKNOWN
    };

    enum class HttpStatus {
        OK = 200,
        CREATED = 201,
        ACCEPTED = 202,
        NO_CONTENT = 204,
        BAD_REQUEST = 400,
        UNAUTHORIZED = 401,
        FORBIDDEN = 403,
        NOT_FOUND = 404,
        METHOD_NOT_ALLOWED = 405,
        INTERNAL_SERVER_ERROR = 500,
        NOT_IMPLEMENTED = 501,
        BAD_GATEWAY = 502,
        SERVICE_UNAVAILABLE = 503
    };

    struct Version {
        int major;
        int minor;
    };

    class QueryParams {
    public:
        explicit QueryParams(const std::string& query_string) {
            parse_query_string(query_string);
        }

        std::string get(const std::string& key) const {
            auto it = params_.find(key);
            return (it != params_.end()) ? it->second : "";
        }

        bool has(const std::string& key) const {
            return params_.find(key) != params_.end();
        }

        int get_int(const std::string& key) const {
            try {
                return std::stoi(get(key));
            } catch (const std::exception&) {
                return 0;
            }
        }

        double get_double(const std::string& key) const {
            try {
                return std::stod(get(key));
            } catch (const std::exception&) {
                return 0.0;
            }
        }

        bool get_bool(const std::string& key) const {
            std::string value = get(key);
            std::transform(value.begin(), value.end(), value.begin(), ::tolower);
            return value == "true" || value == "1" || value == "yes";
        }

        std::string get_string(const std::string& key) const {
            return get(key);
        }

        const std::map<std::string, std::string>& get_all() const {
            return params_;
        }

    private:
        std::map<std::string, std::string> params_;

        void parse_query_string(const std::string& query_string) {
            auto pairs = split(query_string, '&');
            for (const auto& pair : pairs) {
                auto kv = split(pair, '=');
                if (kv.size() == 2) {
                    params_[kv[0]] = kv[1];
                } else if (kv.size() == 1) {
                    params_[kv[0]] = "";
                }
            }
        }

        std::vector<std::string> split(const std::string& str, char delim) {
            std::vector<std::string> tokens;
            std::string token;
            std::istringstream tokenStream(str);
            while (std::getline(tokenStream, token, delim)) {
                tokens.push_back(token);
            }
            return tokens;
        }
    };

    struct Request {
        Method method;
        std::string uri;
        Version version;
        std::map<std::string, std::string> headers;
        std::string body;
        QueryParams query_params;

        Request() : method(Method::GET), version({1, 1}), query_params("") {}

        Request(Method m, const std::string& u, Version v,
                const std::map<std::string, std::string>& h,
                const std::string& b)
                : method(m), version(v), headers(h), body(b), query_params("")
        {
            size_t query_start = u.find('?');
            if (query_start != std::string::npos) {
                uri = u.substr(0, query_start);
                query_params = QueryParams(u.substr(query_start + 1));
            } else {
                uri = u;
            }
        }

        std::string get_header(const std::string& key) const {
            auto it = headers.find(key);
            return (it != headers.end()) ? it->second : "";
        }

        bool has_header(const std::string& key) const {
            return headers.find(key) != headers.end();
        }
    };

    struct Response {
        Version version;
        HttpStatus status;
        std::map<std::string, std::string> headers;
        std::string body;

        std::string status_message() const {
            switch (status) {
                case HttpStatus::OK: return "OK";
                case HttpStatus::CREATED: return "Created";
                case HttpStatus::ACCEPTED: return "Accepted";
                case HttpStatus::NO_CONTENT: return "No Content";
                case HttpStatus::BAD_REQUEST: return "Bad Request";
                case HttpStatus::UNAUTHORIZED: return "Unauthorized";
                case HttpStatus::FORBIDDEN: return "Forbidden";
                case HttpStatus::NOT_FOUND: return "Not Found";
                case HttpStatus::METHOD_NOT_ALLOWED: return "Method Not Allowed";
                case HttpStatus::INTERNAL_SERVER_ERROR: return "Internal Server Error";
                case HttpStatus::NOT_IMPLEMENTED: return "Not Implemented";
                case HttpStatus::BAD_GATEWAY: return "Bad Gateway";
                case HttpStatus::SERVICE_UNAVAILABLE: return "Service Unavailable";
                default: return "Unknown Status";
            }
        }
    };

    inline std::string trim(const std::string& str) {
        auto start = std::find_if_not(str.begin(), str.end(), ::isspace);
        auto end = std::find_if_not(str.rbegin(), str.rend(), ::isspace).base();
        return (start < end ? std::string(start, end) : std::string());
    }

    inline std::vector<std::string> split(const std::string& str, char delim) {
        std::vector<std::string> tokens;
        std::string token;
        std::istringstream tokenStream(str);
        while (std::getline(tokenStream, token, delim)) {
            tokens.push_back(token);
        }
        return tokens;
    }

    // Parsers
    inline Method string_to_method(const std::string& method) {
        if (method == "GET") return Method::GET;
        if (method == "HEAD") return Method::HEAD;
        if (method == "POST") return Method::POST;
        if (method == "PUT") return Method::PUT;
        if (method == "DELETE") return Method::DELETE;
        if (method == "CONNECT") return Method::CONNECT;
        if (method == "OPTIONS") return Method::OPTIONS;
        if (method == "TRACE") return Method::TRACE;
        if (method == "PATCH") return Method::PATCH;
        return Method::UNKNOWN;
    }

    inline std::string method_to_string(Method method) {
        switch (method) {
            case Method::GET: return "GET";
            case Method::HEAD: return "HEAD";
            case Method::POST: return "POST";
            case Method::PUT: return "PUT";
            case Method::DELETE: return "DELETE";
            case Method::CONNECT: return "CONNECT";
            case Method::OPTIONS: return "OPTIONS";
            case Method::TRACE: return "TRACE";
            case Method::PATCH: return "PATCH";
            default: return "UNKNOWN";
        }
    }

    inline Request parse_request(const std::string& raw_request) {
        Request request;
        std::istringstream stream(raw_request);
        std::string line;

        std::getline(stream, line);
        auto parts = split(line, ' ');
        if (parts.size() >= 3) {
            request.method = string_to_method(parts[0]);
            request.uri = parts[1];
            auto version_parts = split(parts[2].substr(5), '.');
            request.version = {std::stoi(version_parts[0]), std::stoi(version_parts[1])};
        }

        while (std::getline(stream, line) && line != "\r") {
            auto colon_pos = line.find(':');
            if (colon_pos != std::string::npos) {
                auto key = trim(line.substr(0, colon_pos));
                auto value = trim(line.substr(colon_pos + 1));
                request.headers[key] = value;
            }
        }

        std::string body((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());
        request.body = body;

        return request;
    }

    inline std::string construct_response(const Response& response) {
        std::ostringstream stream;
        stream << "HTTP/" << response.version.major << "." << response.version.minor << " "
               << static_cast<int>(response.status) << " " << response.status_message() << "\r\n";

        for (const auto& header : response.headers) {
            stream << header.first << ": " << header.second << "\r\n";
        }

        stream << "\r\n" << response.body;
        return stream.str();
    }

    inline Response HTTP_200_OK(const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, HttpStatus::OK, std::move(headers), body.stringify()};
    }

    inline Response HTTP_201_CREATED(const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, HttpStatus::CREATED, std::move(headers), body.stringify()};
    }

    inline Response HTTP_400_BAD_REQUEST(const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, HttpStatus::BAD_REQUEST, std::move(headers), body.stringify()};
    }

    inline Response HTTP_404_NOT_FOUND(const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, HttpStatus::NOT_FOUND, std::move(headers), body.stringify()};
    }

    inline Response HTTP_500_INTERNAL_SERVER_ERROR(const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, HttpStatus::INTERNAL_SERVER_ERROR, std::move(headers), body.stringify()};
    }

    inline Response custom_response(HttpStatus status, const JSON& body = JSON(), std::map<std::string, std::string> headers = {{"Content-Type", "application/json"}}) {
        return Response{{1, 1}, status, std::move(headers), body.stringify()};
    }
}

#endif