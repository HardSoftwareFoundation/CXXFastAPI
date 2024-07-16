// Hard Software CXXFastAPI

#ifndef SERVERC___FASTAPI_CPP_H
#define SERVERC___FASTAPI_CPP_H


#include "http_lib.h"
#include <functional>
#include <vector>
#include <memory>
#include <iostream>
#include <atomic>
#include <csignal>
#include <regex>
#include <map>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <cstring>
#include <stdexcept>

namespace fastapi_cpp {
    using Request = http::Request;
    using Response = http::Response;
    using Method = http::Method;

    class Route {
    public:
        virtual Response handle(const Request& request, const std::map<std::string, std::string>& params) const = 0;
        virtual bool matches(const Method& method, const std::string& uri) const = 0;
        virtual std::map<std::string, std::string> extract_params(const std::string& uri) const = 0;
        virtual const std::string& get_path_pattern() const = 0;
        virtual const std::regex& get_regex() const = 0;
        virtual const std::vector<std::string>& get_param_names() const = 0;
        virtual Method get_method() const = 0;
        virtual ~Route() = default;
    };

    template<typename Func>
    class FunctionRoute : public Route {
        Method method;
        std::string path_pattern;
        std::regex path_regex;
        std::vector<std::string> param_names;
        Func handler;

    public:
        FunctionRoute(Method m, std::string p, Func h)
                : method(m), path_pattern(std::move(p)), handler(std::move(h)) {
            std::string pattern = "^";
            std::regex param_regex(R"(\{([^}]+)\})");
            std::string::const_iterator search_start(path_pattern.cbegin());
            std::smatch match;

            while (std::regex_search(search_start, path_pattern.cend(), match, param_regex)) {
                pattern += std::string(search_start, match.prefix().second);
                pattern += "([^/]+)";
                param_names.push_back(match[1]);
                search_start = match.suffix().first;
            }

            pattern += std::string(search_start, path_pattern.cend());
            pattern += "(?:\\?.*)?$";

            path_regex = std::regex(pattern);
            std::cout << "Route created: " << method_to_string(method) << " " << path_pattern << std::endl;
            std::cout << "Regex pattern: " << pattern << std::endl;
        }

        bool matches(const Method& m, const std::string& uri) const override {
            if (method != m) return false;

            auto query_pos = uri.find('?');
            std::string path = (query_pos != std::string::npos) ? uri.substr(0, query_pos) : uri;

            return std::regex_match(path, path_regex);
        }


        std::map<std::string, std::string> extract_params(const std::string& uri) const override {
            std::map<std::string, std::string> params;
            std::smatch match;
            std::string uri_without_query = uri.substr(0, uri.find('?'));
            if (std::regex_match(uri_without_query, match, path_regex)) {
                for (size_t i = 0; i < param_names.size(); i++) {
                    params[param_names[i]] = match[i + 1].str();
                }
            }
            return params;
        }

        Response handle(const Request& request, const std::map<std::string, std::string>& params) const override {
            auto query_params = parse_query_string(request.uri);

            auto all_params = params;
            all_params.insert(query_params.begin(), query_params.end());

            return handler(request, all_params);
        }

        const std::string& get_path_pattern() const override {
            return path_pattern;
        }

        const std::regex& get_regex() const override {
            return path_regex;
        }

        const std::vector<std::string>& get_param_names() const override {
            return param_names;
        }

        Method get_method() const override {
            return method;
        }
    private:
        std::map<std::string, std::string> parse_query_string(const std::string& uri) const {
            std::map<std::string, std::string> query_params;
            auto query_pos = uri.find('?');
            if (query_pos != std::string::npos) {
                std::string query = uri.substr(query_pos + 1);
                std::istringstream iss(query);
                std::string pair;
                while (std::getline(iss, pair, '&')) {
                    auto eq_pos = pair.find('=');
                    if (eq_pos != std::string::npos) {
                        std::string key = pair.substr(0, eq_pos);
                        std::string value = pair.substr(eq_pos + 1);
                        query_params[key] = value;
                    }
                }
            }
            return query_params;
        }
    };

    class FastAPI {
    public:
        FastAPI() {
            running = false;
            //server_fd = -1;
            //instance = this;
        }

        ~FastAPI() {
            stop();
        }

        template<typename Func>
        void add_route(Method method, const std::string& path, Func handler) {
            routes.push_back(std::make_unique<FunctionRoute<Func>>(method, path, std::move(handler)));
        }

        void get(const std::string& path, std::function<Response(const Request&, const std::map<std::string, std::string>&)> handler) {
            add_route(Method::GET, path, std::move(handler));
        }

        void post(const std::string& path, std::function<Response(const Request&, const std::map<std::string, std::string>&)> handler) {
            add_route(Method::POST, path, std::move(handler));
        }

        void put(const std::string& path, std::function<Response(const Request&, const std::map<std::string, std::string>&)> handler) {
            add_route(Method::PUT, path, std::move(handler));
        }

        void patch(const std::string& path, std::function<Response(const Request&, const std::map<std::string, std::string>&)> handler) {
            add_route(Method::PATCH, path, std::move(handler));
        }

        void delete_(const std::string& path, std::function<Response(const Request&, const std::map<std::string, std::string>&)> handler) {
            add_route(Method::DELETE, path, std::move(handler));
        }

        Response handle_request(const Request& req) {
            std::cout << "Handling request: " << method_to_string(req.method) << " " << req.uri << std::endl;

            for (const auto& route : routes) {
                try {
                    std::cout << "Checking route: " << method_to_string(route->get_method()) << " " << route->get_path_pattern() << std::endl;

                    if (route->matches(req.method, req.uri)) {
                        std::cout << "Route matched!" << std::endl;
                        auto params = route->extract_params(req.uri);

                        for (const auto& [key, value] : params) {
                            std::cout << "Param: " << key << " = " << value << std::endl;
                        }

                        return route->handle(req, params);
                    } else {
                        std::cout << "Route did not match" << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error in route handling: " << e.what() << std::endl;
                }
            }

            std::cout << "No matching route found, returning 404" << std::endl;
            return http::HTTP_404_NOT_FOUND();
        }

        void run(int port) {
            int server_fd;
            struct sockaddr_in address;
            int addrlen = sizeof(address);
            char buffer[4096] = {0};

            if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) == 0) {
                throw std::runtime_error("Socket creation failed");
            }

            address.sin_family = AF_INET;
            address.sin_addr.s_addr = INADDR_ANY;
            address.sin_port = htons(port);

            if (bind(server_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
                close(server_fd);
                throw std::runtime_error("Bind failed");
            }

            if (listen(server_fd, 3) < 0) {
                close(server_fd);
                throw std::runtime_error("Listen failed");
            }

            std::cout << "Server listening on port " << port << std::endl;

            //std::signal(SIGINT, signal_handler);
            //std::signal(SIGTERM, signal_handler);

            running = true;

            while (running) {
                fd_set readfds;
                FD_ZERO(&readfds);
                FD_SET(server_fd, &readfds);

                struct timeval timeout;
                timeout.tv_sec = 1;
                timeout.tv_usec = 0;

                int activity = select(server_fd + 1, &readfds, NULL, NULL, &timeout);

                if (activity < 0 && errno != EINTR) {
                    std::cerr << "Select error" << std::endl;
                    continue;
                }

                if (!running) break;

                if (activity == 0) continue;

                int new_socket;
                if ((new_socket = accept(server_fd, (struct sockaddr *)&address, (socklen_t*)&addrlen)) < 0) {
                    std::cerr << "Accept failed" << std::endl;
                    continue;
                }

                int valread = read(new_socket, buffer, 4096);
                if (valread < 0) {
                    std::cerr << "Read failed" << std::endl;
                    close(new_socket);
                    continue;
                }

                std::string request_str(buffer);
                std::cout << "Received request:\n" << request_str << std::endl;

                try {
                    Request req = http::parse_request(request_str);
                    Response resp = handle_request(req);
                    std::string response_str = http::construct_response(resp);

                    std::cout << "Sending response:\n" << response_str << std::endl;

                    if (send(new_socket, response_str.c_str(), response_str.length(), 0) < 0) {
                        std::cerr << "Send failed" << std::endl;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Error handling request: " << e.what() << std::endl;
                }
                close(new_socket);
            }

            std::cout << "Server stopped" << std::endl;
        }
        void stop() {
            running = false;
            if (server_fd != -1) {
                close(server_fd);
                server_fd = -1;
            }
        }

    private:
        std::vector<std::unique_ptr<Route>> routes;
        std::atomic<bool> running;
        int server_fd;
        static FastAPI* instance;

        static void signal_handler(int signal) {
            std::cout << "Received signal " << signal << ". Shutting down..." << std::endl;
            if (instance) {
                instance->stop();
            }
        }
    };
}
#endif //SERVERC___FASTAPI_CPP_H
