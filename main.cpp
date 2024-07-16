// Hard Software CXXFastAPI

#include "CXXFastAPI/FastAPI_CPP.h"

int main() {
    fastapi_cpp::FastAPI app;

    app.get("/", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        return http::HTTP_200_OK(http::JSON::object({{"message", "Welcome"}}));
    });

    app.get("/param_query", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        http::JSON::Object response_data;
        for (const auto& [key, value] : params) {
            response_data[key] = value;
        }
        return http::HTTP_200_OK(response_data);
    });

    app.get("/echo", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        return http::HTTP_200_OK(http::JSON::object({{"message", "Echo"}}));
    });

    app.post("/echo", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        try {
            http::JSON parsed_json = http::JSON::parse(request.body);
            std::map<std::string, http::JSON> parsed_body = http::JSON::json_to_map(parsed_json);

            http::JSON::Object response_body;
            for (const auto& [key, value] : parsed_body) {
                if (std::holds_alternative<std::string>(value.get_value())) {
                    response_body[key] = std::get<std::string>(value.get_value());
                } else if (std::holds_alternative<int>(value.get_value())) {
                    response_body[key] = std::get<int>(value.get_value());
                } else if (std::holds_alternative<double>(value.get_value())) {
                    response_body[key] = std::get<double>(value.get_value());
                } else if (std::holds_alternative<bool>(value.get_value())) {
                    response_body[key] = std::get<bool>(value.get_value());
                } else if (std::holds_alternative<std::nullptr_t>(value.get_value())) {
                    response_body[key] = nullptr;
                }
            }

            response_body["message"] = "post successful";
            return http::HTTP_200_OK(http::JSON(response_body));
        } catch (const std::exception& e) {
            return http::HTTP_400_BAD_REQUEST(http::JSON::object({{"error", e.what()}}));
        }
    });

    app.get("/test", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        return http::HTTP_200_OK(http::JSON::object({{"message", "Testing"}}));
    });

    app.get("/echo/{echo}", [](const fastapi_cpp::Request& request, const std::map<std::string, std::string>& params) {
        auto to_echo = params.at("echo");
        return http::HTTP_200_OK(http::JSON::object({{"Echo route", to_echo}}));
    });

    app.run(8000);

    return 0;
}