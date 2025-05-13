#pragma once
#include <string>

class Logger {
private:
    FILE* logFile;

    std::string getCurrentDate() const;
    std::string getCurrentTime() const;

public:
    Logger();
    ~Logger();

    void logAction(const std::string& entity, const std::string& action);
};