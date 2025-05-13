#include "Logger.h"
#include <ctime>
#include <iostream>
#include <cstdio>

Logger::Logger() {
    /*fopen_s(&logFile, "logger.txt", "a");
    if (!logFile) {
        throw std::runtime_error("Unable to open log file: logger.txt");
    }*/
}

Logger::~Logger() {
   /* if (logFile) {
        fclose(logFile);
    }*/
}

std::string Logger::getCurrentDate() const {
    time_t now = time(nullptr);
    tm localTime;
    localtime_s(&localTime, &now);
    char buffer[11];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d", &localTime);
    return std::string(buffer);
}

std::string Logger::getCurrentTime() const {
    time_t now = time(nullptr);
    tm localTime;
    localtime_s(&localTime, &now);
    char buffer[9];
    strftime(buffer, sizeof(buffer), "%H:%M:%S", &localTime);
    return std::string(buffer);
}

void Logger::logAction(const std::string& entity, const std::string& action) {
    fopen_s(&logFile, "logger.txt", "a");
    if (!logFile) {
        throw std::runtime_error("Unable to open log file: logger.txt");
    }
    std::string date = getCurrentDate();
    std::string time = getCurrentTime();
    std::string logEntry = date + " " + time + " " + entity + " " + action + "\n";

    if (logFile) {
        fprintf(logFile, "%s", logEntry.c_str());
        fflush(logFile);
    }
    if (logFile) {
        fclose(logFile);
    }
    std::cout << "Log: " << logEntry;
}