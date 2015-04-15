#pragma once
#include <fstream>
#include <sstream>
#include <string>

class Logger
{
public:
    Logger(void);
    ~Logger(void);

    static Logger* getInstance()
    {
        if (Logger::instance == NULL)
            Logger::instance = new Logger();
        return Logger::instance;
    }

    void initialize(std::string fileName);
    void uninitialize();

    void write(std::string line);
    void write(const char* format, ...);

private:
    static Logger* instance;
    std::fstream* logFile;

    void writePrefix();
};

