#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <windows.h>

namespace ui {

    // Theme Colors (TrueColor ANSI sequences)
    const std::string REAL_RESET = "\033[0m";
    const std::string TEXT_COLOR = "\033[38;2;255;240;180m"; // Pale Gold for regular text
    const std::string BLACK_BG = "\033[48;2;0;0;0m"; // Pure Black
    const std::string RESET = REAL_RESET + TEXT_COLOR + BLACK_BG; // Overwrite RESET to always return to theme
    
    const std::string GOLD = "\033[38;2;255;215;0m";
    const std::string DARK_GOLD = "\033[38;2;184;134;11m";
    const std::string RED = "\033[38;2;255;100;0m"; // Orange-Red for errors
    const std::string GREEN = "\033[38;2;255;223;0m"; // Golden Yellow for success
    const std::string GRAY = "\033[38;2;160;140;90m"; // Muted Gold for subtitles

    inline void EnableANSI() {
        HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
        if (hOut == INVALID_HANDLE_VALUE) return;
        DWORD dwMode = 0;
        if (!GetConsoleMode(hOut, &dwMode)) return;
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
        
        // Clear screen and set background
        std::cout << BLACK_BG << "\033[2J\033[1;1H" << std::flush;
    }

    inline void PrintAnimated(const std::string& text, int delayMs = 3) {
        bool in_ansi = false;
        for (size_t i = 0; i < text.length(); ++i) {
            char c = text[i];
            if (c == '\033') {
                in_ansi = true;
            }
            
            std::cout << c << std::flush;
            
            if (in_ansi && c == 'm') {
                in_ansi = false;
                continue;
            }
            
            if (!in_ansi && c != ' ' && c != '\n' && c != '\r') {
                std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
            }
        }
    }

    inline void PrintHeader(const std::string& title) {
        const int WIDTH = 56; // Fixed inner text width
        std::cout << "\n";
        
        // Border: 4 spaces padding, '+', WIDTH+2 dashes, '+'
        PrintAnimated(GOLD + "    +" + std::string(WIDTH + 2, '-') + "+\n", 1);
        
        // Title line
        int padding = (WIDTH - title.length()) / 2;
        std::string leftPad(padding, ' ');
        std::string rightPad(WIDTH - title.length() - padding, ' ');
        PrintAnimated("    | " + DARK_GOLD + leftPad + title + rightPad + GOLD + " |\n", 2);

        // Subtitle line
        std::string subtitle = "Made by AK and Natsu";
        int subPadding = (WIDTH - subtitle.length()) / 2;
        std::string subLeftPad(subPadding, ' ');
        std::string subRightPad(WIDTH - subtitle.length() - subPadding, ' ');
        PrintAnimated("    | " + GRAY + subLeftPad + subtitle + subRightPad + GOLD + " |\n", 2);

        // Bottom border
        PrintAnimated("    +" + std::string(WIDTH + 2, '-') + "+\n" + RESET + BLACK_BG + "\n", 1);
    }

    inline void PrintInfo(const std::string& msg) {
        PrintAnimated(GOLD + "    [*] " + RESET + BLACK_BG + msg + "\n", 3);
    }

    inline void PrintSuccess(const std::string& msg) {
        PrintAnimated(GREEN + "    [+] " + RESET + BLACK_BG + msg + "\n", 3);
    }

    inline void PrintError(const std::string& msg) {
        PrintAnimated(RED + "    [-] " + RESET + BLACK_BG + msg + "\n", 3);
    }

    inline std::string GetInput(const std::string& prompt) {
        PrintAnimated(GOLD + "    > " + RESET + BLACK_BG + prompt, 3);
        std::string input;
        std::getline(std::cin, input);
        // Trim trailing
        while (!input.empty() && (input.back() == '\r' || input.back() == '\n' || input.back() == ' ' || input.back() == '\t')) {
            input.pop_back();
        }
        // Trim leading
        size_t start = 0;
        while (start < input.length() && (input[start] == ' ' || input[start] == '\t' || input[start] == '\r' || input[start] == '\n')) {
            start++;
        }
        return input.substr(start);
    }

    inline void SpinnerWait(int durationMs, const std::string& msg) {
        const char spinner[] = {'|', '/', '-', '\\'};
        int steps = durationMs / 100;
        
        std::cout << GOLD << "    [*] " << RESET << BLACK_BG << msg << " ";
        
        for (int i = 0; i < steps; ++i) {
            std::cout << GOLD << spinner[i % 4] << "\b" << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        std::cout << " \n" << RESET << BLACK_BG;
    }

    inline void BootAnimation() {
        std::cout << "\033[?25l"; // Hide cursor
        std::cout << BLACK_BG << "\033[2J\033[1;1H" << std::flush;
        
        const std::vector<std::string> art = {
            "  _   _       _           __  __    _    _  __",
            " | \\ | | __ _| |_ ___ _   \\ \\/ /   / \\  | |/ /",
            " |  \\| |/ _` | __/ __| | | \\  /   / _ \\ | ' / ",
            " | |\\  | (_| | |_\\__ \\ |_| /  \\  / ___ \\| . \\ ",
            " |_| \\_|\\__,_|\\__|___/\\__,_/_/\\_\\/_/   \\_\\_|\\_\\"
        };
        
        int steps = 20;
        for (int i = 0; i <= steps; ++i) {
            std::cout << "\033[1;1H"; // Move to top-left
            std::cout << "\n\n";
            int r = (255 * i) / steps;
            int g = (215 * i) / steps;
            int b = 0;
            
            std::string color = "\033[38;2;" + std::to_string(r) + ";" + std::to_string(g) + ";" + std::to_string(b) + "m";
            
            for (const auto& line : art) {
                std::cout << color << line << "\n";
            }
            std::cout << "\n    \033[38;2;160;140;90mInitializing security protocols...\033[0m\033[48;2;0;0;0m\n";
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(800));
        std::cout << "\033[?25h"; // Show cursor
        std::cout << BLACK_BG << TEXT_COLOR << "\033[2J\033[1;1H" << std::flush;
    }

} // namespace ui
