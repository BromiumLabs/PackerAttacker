#pragma once
#include <fstream>
#include <sstream>
#include <string>

#define _LOG_BASE_ __FUNCTION__, __LINE__
#define LOG_ERROR "%s ERROR %s (%d) ", _LOG_BASE_
#define LOG_INFO  "%s INFO  %s (%d) ", _LOG_BASE_
#define LOG_WARN  "%s WARN  %s (%d) ", _LOG_BASE_
#define LOG_APPENDLINE "                            ", _LOG_BASE_

class SyncLock;
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

    void write(const char* prefixFormat, const char* function, int lineNumber, std::string line);
    void write(const char* prefixFormat, const char* function, int lineNumber, const char* format, ...);

private:
    static Logger* instance;
    std::fstream* logFile;
	SyncLock* lock;

    void writePrefix(const char* prefixFormat, const char* function, int lineNumber);
};

