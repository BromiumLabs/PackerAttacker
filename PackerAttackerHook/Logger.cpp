#include "Logger.h"
#include "SyncLock.h"

#include <assert.h>
#include <stdarg.h>
#include <time.h>

Logger* Logger::instance= NULL;

Logger::Logger(void)
{
	this->lock = new SyncLock();
}
Logger::~Logger(void)
{
	delete this->lock;
}
void Logger::initialize(std::string fileName)
{
    this->logFile = new std::fstream(fileName, std::ios::out);
}
void Logger::uninitialize()
{
    assert(this->logFile);
    this->logFile->close();
    delete this->logFile;
}

void Logger::write(const char* prefixFormat, const char* function, int lineNumber, std::string line)
{
    assert(this->logFile);
    //assert(this->logFile->open());

	auto sg = this->lock->enterWithScopeGuard();

    this->writePrefix(prefixFormat, function, lineNumber);
    this->logFile->write(line.c_str(), line.length());

    if (line[line.length() - 1] != '\n')
        this->logFile->write("\n", 1);

    this->logFile->flush();
}
void Logger::write(const char* prefixFormat, const char* function, int lineNumber, const char* format, ...)
{
	char buffer[4096];
    for (int i = 0; i < 4096; i++)
        buffer[i] = 0x00;

	va_list marker;
	va_start(marker, format);
	vsprintf_s(buffer, sizeof(buffer), format, marker);
	va_end(marker);

    this->write(prefixFormat, function, lineNumber, std::string(buffer));
}

void Logger::writePrefix(const char* prefixFormat, const char* function, int lineNumber)
{
    time_t now = time(0);
    struct tm  tstruct;
    char timebuffer[128], buffer[128];
    
    tstruct = *localtime(&now);
    strftime(timebuffer, sizeof(timebuffer), "[%Y-%m-%d.%X]", &tstruct);

	sprintf(buffer, prefixFormat, timebuffer, function, lineNumber);
	this->logFile->write(buffer, strlen(buffer));
}