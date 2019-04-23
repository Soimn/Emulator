#include <windows.h>

typedef unsigned __int8  U8;
typedef unsigned __int16 U16;
typedef unsigned __int32 U32;
typedef unsigned __int64 U64;

typedef __int8   I8;
typedef __int16  I16;

typedef size_t Memory_Index;

typedef U32 bool;
#define true 1
#define false 0

#define Assert(EX) if ((EX)); else *(volatile int*)0 = 0;
#define ARRAY_COUNT(array) (sizeof(array) / sizeof(array[0]))

typedef struct String
{
    Memory_Index size;
    char* data;
} String;

#define CONST_STRING(string) {.size = sizeof(string) - 1, .data = string}

inline void
ConsoleOut(String message)
{
    U32 chars_written;
    WriteConsoleA(GetStdHandle((U32)-11), message.data, (U32) message.size, (LPDWORD) &chars_written, 0);
}

#define PARSING_ERROR   0
#define PARSING_SUCCESS 1
#define PARSING_DONE    2

typedef U32 Error_Code;

enum OPCODE
{
    NOP, // NOP
    
    MOV, // MOV <Register> <Literal / Register>
    RES, // RES <Register> <Register / Pointer>
    
    JMP, // JMP <Label / Pointer>
    
    CMP, // CMP <Register> <Literal / Register>
    JLT, // JLT <Label / Pointer>
    JGT, // JGT <Label / Pointer>
    JET, // JET <Label / Pointer>
    
    PSH, // PSH
    POP, // POP
    
    ADD, // ADD <Register> <Literal / Register>
    SUB, // SUB <Register> <Literal / Register>
    MUL, // MUL <Register> <Literal / Register>
    DIV, // DIV <Register> <Literal / Register>
    
    AND, // AND <Register> <Literal / Register>
    ROR, // ROR <Register> <Literal / Register>
    NOT, // NOT <Register>
    XOR, // XOR <Register> <Literal / Register>
    XND, // XND <Register> <Literal / Register>
    
    RSH, // RSH <Register> <Literal / Register>
    LSH, // LSH <Register> <Literal / Register>
    
    HLT, // HLT
    
    SEC, // SEC
    CLC, // CLC
    
    RET, // RET
};

enum REGISTER
{
    PRC,
    IPT,
    
    ADX,
    BDX,
    CDX,
    
    STS,
    
    REGISTER_COUNT
};

typedef struct Tokenizer
{
    String input;
    U32 line;
    U32 column;
    char at;
} Tokenizer;

typedef struct Memory_Stream
{
    U8* first;
    U8* next;
    U32 capacity;
} Memory_Stream;

typedef struct Label
{
    String name;
    U16 address;
} Label;

typedef struct Label_Table
{
    Label* first;
    Label* next;
    U32 capacity;
} Label_Table;

inline bool
AppendInstruction(Memory_Stream* stream, U8 opcode, bool x_flag, bool y_flag)
{
    Assert(stream);
    
    bool result = false;
    
    if (stream->capacity > 0)
    {
        *(stream->next++) = opcode | ((U8) x_flag << 7) | ((U8) y_flag << 6);
        --stream->capacity;
    }
    
    return result;
}

inline bool
AppendWord(Memory_Stream* stream, U8 data)
{
    Assert(stream);
    
    bool result = false;
    
    if (stream->capacity > 0)
    {
        *(stream->next++) = data;
        --stream->capacity;
    }
    
    return result;
}

inline bool
AppendDoubleWord(Memory_Stream* stream, U16 data)
{
    bool result = false;
    
    result = AppendWord(stream, (U8)((data & 0xFF00) >> 8));
    result = AppendWord(stream, (U8)((data & 0x00FF) >> 0));
    
    return result;
}

inline void
Advance(Tokenizer* tokenizer)
{
    if (tokenizer->input.size <= 1)
    {
        tokenizer->at = 0;
    }
    
    else
    {
        ++tokenizer->input.data;
        --tokenizer->input.size;
        
        tokenizer->at = tokenizer->input.data[0];
    }
}

inline String
GetToken(Tokenizer* tokenizer)
{
    String result = {0};
    
    if (tokenizer->input.data)
    {
        for (;;)
        {
            while (tokenizer->at == ' ' || tokenizer->at == '\t' || tokenizer->at == '\v')
            {
                Advance(tokenizer);
            }
            
            if (tokenizer->at == '\n' || tokenizer->at == '\r')
            {
                Advance(tokenizer);
                continue;
            }
            
            else if (tokenizer->at == ';')
            {
                while (tokenizer->at && !(tokenizer->at == '\n' || tokenizer->at == '\r'))
                {
                    Advance(tokenizer);
                }
            }
            
            else
            {
                break;
            }
        }
        
        result.data = tokenizer->input.data;
        
        while (tokenizer->at && ((tokenizer->at >= 'A' && tokenizer->at <= 'Z') || (tokenizer->at >= 'a' && tokenizer->at <= 'z') ||
                                 (tokenizer->at >= '0' && tokenizer->at <= '9') || tokenizer->at == ':' || tokenizer->at == '_' || tokenizer->at == '#' || tokenizer->at == '$' || tokenizer->at == '%' || tokenizer->at == ';'))
        {
            Advance(tokenizer);
        }
        
        result.size = tokenizer->input.data - result.data;
        
        if (!tokenizer->at)
        {
            tokenizer->input.data = 0;
            tokenizer->input.size = 0;
            ++result.size;
        }
    }
    
    result.size *= (!!tokenizer->input.size);
    
    return result;
}

inline bool
Strcompare(String string, const char* cstring)
{
    U32 i = 0;
    for (; i < string.size && string.data[i] == cstring[i]; ++i);
    
    return (i == string.size && cstring[i] == 0);
}

inline bool
Stringcompare(String string_1, String string_2)
{
    while((string_1.size && string_2.size)
          && (string_1.data[0] == string_2.data[0]))
    {
        ++string_1.data;
        --string_1.size;
        ++string_2.data;
        --string_2.size;
    }
    
    return !string_1.size && string_1.size == string_2.size;
}

typedef struct Literal
{
    bool is_valid;
    bool is_double_length;
    bool is_pointer;
    U16 value;
} Literal;

inline Literal
ParseLiteral(String token)
{
    Literal result = {.is_valid = false, .value = 0};
    
    if (token.data && token.size)
    {
        if (token.data[0] == '#') ++token.data, --token.size;
        else result.is_pointer = true;
        
        bool is_binary = false;
        bool is_hex    = false;
        
        if (token.size)
        {
            if (token.data[0] == '$') is_hex = true, ++token.data, --token.size;
            else if (token.data[0] == '%') is_binary = true, ++token.data, --token.size;
            
            if (!is_hex && !(token.data[0] >= '0' && token.data[0] <= '9'))
            {
                // Error
            }
            
            else
            {
                if (token.size && ((is_hex && token.size <= 4) || (is_binary && token.size <= 16) || (token.size <= 5)))
                {
                    U64 acc = 0;
                    U16 place_num = 1;
                    U16 base      = (is_binary ? 2 : (is_hex ? 16 : 10));
                    
                    for (U32 i = (U32) token.size - 1; i >= 0 && i < token.size; --i)
                    {
                        if (is_hex && (token.data[i] >= 'A' || token.data[i] <= 'Z'))
                        {
                            acc += place_num * (token.data[i] - 'A' + 10);
                        }
                        
                        else
                        {
                            if (is_binary && (token.data[i] == '0' || token.data[i] == '1'))
                            {
                                acc += place_num * (token.data[i] - '0');
                            }
                            
                            else if (token.data[i] >= '0' && token.data[i] <= '9')
                            {
                                acc += place_num * (token.data[i] - '0');
                            }
                            
                            else
                            {
                                // Error
                            }
                        }
                        
                        place_num *= base;
                    }
                    
                    if (acc < 65536)
                    {
                        result.value    = (U16) acc;
                        result.is_valid = true;
                        result.is_double_length = (result.value >= 256);
                    }
                    
                    else
                    {
                        // Error
                    }
                }
                
                else
                {
                    // Error
                }
            }
        }
        
        else
        {
            // Error
        }
    }
    
    else
    {
        // Error
    }
    
    return result;
}

#define UNKNOWN_REGISTER_NAME 255

inline U8
ParseRegisterName(String token)
{
    U8 result = UNKNOWN_REGISTER_NAME;
    
    if (token.size == 3)
    {
        if ((token.data[0] >= 'A' && token.data[0] <= 'C') && token.data[1] == 'D' && token.data[2] == 'X')
        {
            result = ADX + (token.data[0] - 'A');
        }
        
        else if (Strcompare(token, "PRC")) result = PRC;
        else if (Strcompare(token, "IPT")) result = IPT;
        else if (Strcompare(token, "STS")) result = STS;
    }
    
    else
    {
        // Error
    }
    
    return result;
}

inline Error_Code
ParseNextInstruction(Tokenizer* tokenizer, Memory_Stream* memory_stream, Label_Table* label_table)
{
    Error_Code result = PARSING_ERROR;
    
    String token = GetToken(tokenizer);
    
    if (token.size)
    {
        if (token.data[0] == ':')
        {
            ++token.data, --token.size;
            if (token.size)
            {
                bool is_invalid = false;
                for (U32 i = 0; i < token.size; ++i)
                {
                    if (!((token.data[i] >= 'A' && token.data[i] <= 'Z') || (token.data[i] >= 'a' && token.data[i] <= 'z') || 
                          token.data[i] == '_'))
                    {
                        is_invalid = true;
                    }
                }
                
                if (!is_invalid)
                {
                    bool found_equal = false;
                    for (Label* scan = label_table->first; scan <= label_table->next; ++scan)
                    {
                        if (scan->name.data && Stringcompare(scan->name, token))
                        {
                            found_equal = true;
                            break;
                        }
                    }
                    
                    if (!found_equal)
                    {
                        if (label_table->capacity >= 1)
                        {
                            label_table->next->name    = token;
                            label_table->next->address = (U16) (memory_stream->next - memory_stream->first);
                            ++label_table->next;
                            --label_table->capacity;
                            
                            result = PARSING_SUCCESS;
                        }
                    }
                    
                    else
                    {
                        // Error
                    }
                }
                
                else
                {
                    // Error
                }
            }
            
            else
            {
                // Error
            }
            
        }
        
        else if (Strcompare(token, "NOP"))
        {
            AppendInstruction(memory_stream, NOP, false, false);
            
            result = PARSING_SUCCESS;
        }
        
        else if (Strcompare(token, "MOV") || Strcompare(token, "CMP"))
        {
            U8 opcode = 0;
            if (token.data[0] == 'M') opcode = MOV;
            else if (token.data[0] == 'C') opcode = CMP;
            
            token = GetToken(tokenizer);
            
            U8 dest_register = ParseRegisterName(token);
            
            if (dest_register == UNKNOWN_REGISTER_NAME)
            {
                // Error
            }
            
            else
            {
                token = GetToken(tokenizer);
                
                Literal literal    = ParseLiteral(token);
                U8 source_register = ParseRegisterName(token);
                
                if (literal.is_valid)
                {
                    AppendInstruction(memory_stream, opcode, literal.is_double_length, true);
                    
                    AppendWord(memory_stream, dest_register);
                    
                    if (literal.is_double_length) AppendDoubleWord(memory_stream, literal.value);
                    else AppendWord(memory_stream, (U8) literal.value);
                    
                    result = PARSING_SUCCESS;
                }
                
                else if (source_register != UNKNOWN_REGISTER_NAME)
                {
                    AppendInstruction(memory_stream, opcode, false, false);
                    AppendWord(memory_stream, dest_register);
                    AppendWord(memory_stream, source_register);
                    
                    result = PARSING_SUCCESS;
                }
                
                else
                {
                    // Error
                }
            }
        }
        
        else if (Strcompare(token, "RES"))
        {
            token = GetToken(tokenizer);
            
            U8 dest_register = ParseRegisterName(token);
            
            if (dest_register == UNKNOWN_REGISTER_NAME)
            {
                // Error
            }
            
            else
            {
                token = GetToken(tokenizer);
                Literal literal    = ParseLiteral(token);
                U8 source_register = ParseRegisterName(token);
                
                if (literal.is_valid)
                {
                    AppendInstruction(memory_stream, RES, literal.is_double_length, true);
                    
                    if (literal.is_double_length) AppendDoubleWord(memory_stream, literal.value);
                    else AppendWord(memory_stream, (U8) literal.value);
                    
                    result = PARSING_SUCCESS;
                }
                
                else if (source_register != UNKNOWN_REGISTER_NAME)
                {
                    AppendInstruction(memory_stream, RES, source_register, false);
                }
                
                else
                {
                    // Error
                }
            }
        }
        
        else if (Strcompare(token, "JMP") || Strcompare(token, "JLT") || Strcompare(token, "JGT") || Strcompare(token, "JET"))
        {
            U8 opcode = 0;
            if (token.data[1] == 'M') opcode = JMP;
            else if (token.data[1] == 'L') opcode = JLT;
            else if (token.data[1] == 'G') opcode = JGT;
            else if (token.data[1] == 'E') opcode = JET;
            
            token = GetToken(tokenizer);
            Literal literal = ParseLiteral(token);
            
            if (literal.is_valid)
            {
                if (literal.is_pointer)
                {
                    AppendInstruction(memory_stream, opcode, (literal.is_double_length), false);
                    if (literal.is_double_length) AppendDoubleWord(memory_stream, literal.value);
                    else AppendWord(memory_stream, (U8) literal.value);
                }
                
                else
                {
                    // Error
                }
            }
            
            else
            {
                bool is_invalid = false;
                for (U32 i = 0; i < token.size; ++i)
                {
                    if (!((token.data[i] >= 'A' && token.data[i] <= 'Z') || (token.data[i] >= 'a' && token.data[i] <= 'z') ||
                          token.data[i] == '_'))
                    {
                        is_invalid = true;
                    }
                }
                
                if (!is_invalid)
                {
                    Label* found_equal = 0;
                    for (Label* scan = label_table->first; scan <= label_table->next; ++scan)
                    {
                        if (scan->name.data && Stringcompare(scan->name, token))
                        {
                            found_equal = scan;
                            break;
                        }
                    }
                    
                    if (found_equal)
                    {
                        AppendInstruction(memory_stream, opcode, (found_equal->address >= 256), false);
                        if (found_equal->address >= 256) AppendDoubleWord(memory_stream, found_equal->address);
                        else AppendWord(memory_stream, (U8) found_equal->address);
                        
                        result = PARSING_SUCCESS;
                    }
                    
                    else
                    {
                        // Error
                    }
                }
                
                else
                {
                    // Error
                }
            }
        }
        
        else if (Strcompare(token, "PSH")) AppendInstruction(memory_stream, PSH, false, false);
        else if (Strcompare(token, "POP")) AppendInstruction(memory_stream, POP, false, false);
        
        else if (Strcompare(token, "ADD") || Strcompare(token, "SUB") || Strcompare(token, "MUL") || Strcompare(token, "DIV") || Strcompare(token, "AND") || Strcompare(token, "ROR") || Strcompare(token, "XOR") || Strcompare(token, "XND") || Strcompare(token, "RSH") || Strcompare(token, "LSH"))
        {
            U8 opcode = 0;
            
            if (token.data[0] == 'A' && token.data[1] == 'D') opcode = ADD;
            else if (token.data[0] == 'S') opcode = SUB;
            else if (token.data[0] == 'M') opcode = MUL;
            else if (token.data[0] == 'D') opcode = DIV;
            else if (token.data[0] == 'A') opcode = AND;
            else if (token.data[0] == 'R' && token.data[0] == 'O') opcode = ROR;
            else if (token.data[0] == 'X' && token.data[0] == 'O') opcode = XOR;
            else if (token.data[0] == 'X') opcode = XND;
            else if (token.data[0] == 'R') opcode = RSH;
            else if (token.data[0] == 'L') opcode = LSH;
            
            token = GetToken(tokenizer);
            
            U8 dest_register = ParseRegisterName(token);
            
            if (dest_register == UNKNOWN_REGISTER_NAME)
            {
                // Error
            }
            
            else
            {
                token = GetToken(tokenizer);
                Literal literal    = ParseLiteral(token);
                U8 source_register = ParseRegisterName(token);
                
                if (literal.is_valid)
                {
                    AppendInstruction(memory_stream, opcode, (literal.is_double_length), false);
                    AppendWord(memory_stream, dest_register);
                    
                    if (literal.is_double_length) AppendDoubleWord(memory_stream, literal.value);
                    else AppendWord(memory_stream, (U8) literal.value);
                    
                    result = PARSING_SUCCESS;
                }
                
                else if (source_register != UNKNOWN_REGISTER_NAME)
                {
                    AppendInstruction(memory_stream, opcode, false, true);
                    AppendWord(memory_stream, dest_register);
                    AppendWord(memory_stream, source_register);
                }
                
                else
                {
                    // Error
                }
            }
        }
        
        else if (Strcompare(token, "HLT")) AppendInstruction(memory_stream, HLT, false, false);
        else if (Strcompare(token, "SEC")) AppendInstruction(memory_stream, SEC, false, false);
        else if (Strcompare(token, "CLC")) AppendInstruction(memory_stream, CLC, false, false);
        else if (Strcompare(token, "RET")) AppendInstruction(memory_stream, RET, false, false);
        
        else
        {
            // Error
        }
    }
    
    else
    {
        result = PARSING_DONE;
    }
    
    return result;
}

int
wmain(int argc, wchar_t* argv[], wchar_t* envp[])
{
    envp;
    
    int result = -1;
    
    if (argc < 2 || argc > 3)
    {
        String to_print = CONST_STRING("Invalid number of arguments passed to the program");
        ConsoleOut(to_print);
    }
    
    else
    {
        U32 input_length = 0;
        while (argv[1][input_length])
        {
            ++input_length;
        }
        
        wchar_t* path = argv[1];
        if (path[0] == L'"')
        {
            ++path, --input_length;
            
            if (path[input_length - 2] == '"') --input_length;
            else
            {
                String to_print = CONST_STRING("The passed path contained a start quote, but no end quote");
                ConsoleOut(to_print);
            }
        }
        
        HANDLE file_handle = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
        
        if (file_handle == INVALID_HANDLE_VALUE)
        {
            String to_print = CONST_STRING("The passed path points to a file that does not exist");
            ConsoleOut(to_print);
        }
        
        else
        {
            LARGE_INTEGER wfile_size = {0};
            if (GetFileSizeEx(file_handle, &wfile_size))
            {
                U32 file_size = (U32) wfile_size.QuadPart;
                
                void* file_memory = VirtualAlloc(0, file_size + 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                
                if (file_memory)
                {
                    U32 bytes_read = 0;
                    bool succeeded_read = ReadFile(file_handle, file_memory, file_size, (LPDWORD) &bytes_read, 0);
                    
                    if (!succeeded_read || bytes_read != file_size)
                    {
                        String to_print = CONST_STRING("Failed to read the contents of the file");
                        ConsoleOut(to_print);
                    }
                    
                    else
                    {
                        Tokenizer tokenizer = {0};
                        tokenizer.input.size = file_size;
                        tokenizer.input.data = file_memory;
                        tokenizer.at = tokenizer.input.data[0];
                        
                        void* out_memory = VirtualAlloc(0, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                        
                        if (out_memory)
                        {
                            Memory_Stream memory_stream = {0};
                            memory_stream.first = out_memory;
                            memory_stream.next = memory_stream.first;
                            memory_stream.capacity = 65536;
                            
                            wchar_t* out_path = 0;
                            if (argc == 3)
                            {
                                out_path = argv[2];
                            }
                            
                            else
                            {
                                out_path = L"a.out";
                            }
                            
                            HANDLE out_file = CreateFileW(out_path, GENERIC_WRITE, 0, 0, TRUNCATE_EXISTING, 0, 0);
                            
                            if (out_file == INVALID_HANDLE_VALUE)
                            {
                                out_file = CreateFileW(out_path, GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
                            }
                            
                            if (out_file != INVALID_HANDLE_VALUE)
                            {
                                void* label_table_memory = VirtualAlloc(0, 65536 * sizeof(Label), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
                                
                                if (label_table_memory)
                                {
                                    Label_Table label_table = {0};
                                    label_table.first = label_table_memory;
                                    label_table.next = label_table.first;
                                    label_table.capacity = 65536;
                                    
                                    bool encountered_errors = false;
                                    for (;;)
                                    {
                                        Error_Code code = ParseNextInstruction(&tokenizer, &memory_stream, &label_table);
                                        
                                        if (code == PARSING_DONE) break;
                                        else if (code == PARSING_ERROR)
                                        {
                                            encountered_errors = true;
                                            break;
                                        }
                                    }
                                    
                                    if (!encountered_errors)
                                    {
                                        U32 bytes_written = 0;
                                        bool succeeded_write = WriteFile(out_file, memory_stream.first, 65536, (LPDWORD) &bytes_written, 0);
                                        
                                        if (succeeded_write && bytes_written == 65536)
                                        {
                                            CloseHandle(file_handle);
                                            CloseHandle(out_file);
                                            result = 0;
                                        }
                                        
                                        else
                                        {
                                            String to_print = CONST_STRING("Failed to write the result of the parsing to the output binary");
                                            ConsoleOut(to_print);
                                        }
                                    }
                                    
                                    else
                                    {
                                        String to_print = CONST_STRING("Failed to parse the file");
                                        ConsoleOut(to_print);
                                    }
                                }
                                
                                else
                                {
                                    String to_print = CONST_STRING("Failed to allocate memory for the label table");
                                    ConsoleOut(to_print);
                                }
                                
                            }
                            
                            else
                            {
                                String to_print = CONST_STRING("Failed to open the output binary");
                                ConsoleOut(to_print);
                            }
                        }
                        
                        else
                        {
                            String to_print = CONST_STRING("Failed to alloctate memory for the output binary");
                            ConsoleOut(to_print);
                        }
                    }
                }
                
                else
                {
                    if (file_size)
                    {
                        String to_print = CONST_STRING("Failed to allocate memory for the file");
                        ConsoleOut(to_print);
                    }
                    
                    else
                    {
                        String to_print = CONST_STRING("The passed file was empty");
                        ConsoleOut(to_print);
                    }
                }
            }
            
            else
            {
                String to_print = CONST_STRING("Failed to query the size of the specified file");
                ConsoleOut(to_print);
            }
        }
    }
    
    return result;
}