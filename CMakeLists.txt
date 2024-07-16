cmake_minimum_required(VERSION 3.28)
project(CXXFastAPI)

set(CMAKE_CXX_STANDARD 26)

add_executable(CXXFastAPI__ main.cpp
        CXXFastAPI/http_lib.h
        CXXFastAPI/FastAPI_CPP.h
)
