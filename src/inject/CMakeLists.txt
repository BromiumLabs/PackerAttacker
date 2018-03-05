
file(GLOB SOURCE_FILES
    "main.cpp"
)

add_definitions(-DUNICODE)
add_executable(PackerAttackerInject ${SOURCE_FILES})
