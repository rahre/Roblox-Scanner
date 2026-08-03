#pragma once

#include <iostream>
#include <string>
#include <thread>
#include <chrono>
#include <vector>
#include <windows.h>

namespace ui {

    // Theme Colors (TrueColor ANSI sequences)
    const std::string RESET = "\033[0m";
    const std::string GOLD = "\033[38;2;255;215;0m";
    const std::string DARK_GOLD = "\033[38;2;184;134;11m";
    const std::string RED = "\033[38;2;220;20;60m";
    const std::string GREEN = "\033[38;2;50;205;50m";
    const std::string GRAY = "\033[38;2;128;128;128m";
    const std::string BLACK_BG = "\033[48;2;10;10;10m"; // Very dark grey/black

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

    inline void PrintAnimated(const std::string& text, int delayMs = 15) {
        for (char c : text) {
            std::cout << c << std::flush;
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    }

    inline void PrintHeader(const std::string& title) {
        std::cout << "\n";
        std::cout << GOLD << "    +" << std::string(54, '-') << "+\n";
        
        // Center the title precisely
        int padding = (54 - title.length()) / 2;
        std::string paddedTitle = std::string(padding, ' ') + title;
        // Make sure exact 54 width is met
        paddedTitle += std::string(54 - paddedTitle.length(), ' ');

        std::cout << "    | " << DARK_GOLD << paddedTitle << GOLD << " |\n";
        std::cout << "    | " << GRAY << "                 Made by AK and Natsu                 " << GOLD << " |\n";
        std::cout << "    +" << std::string(54, '-') << "+\n" << RESET << BLACK_BG << "\n";
    }

    inline void PrintInfo(const std::string& msg) {
        std::cout << GOLD << "    [*] " << RESET << BLACK_BG << msg << "\n";
    }

    inline void PrintSuccess(const std::string& msg) {
        std::cout << GREEN << "    [+] " << RESET << BLACK_BG << msg << "\n";
    }

    inline void PrintError(const std::string& msg) {
        std::cout << RED << "    [-] " << RESET << BLACK_BG << msg << "\n";
    }

    inline std::string GetInput(const std::string& prompt) {
        std::cout << GOLD << "    > " << RESET << BLACK_BG << prompt;
        std::string input;
        std::getline(std::cin, input);
        return input;
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

} // namespace ui
