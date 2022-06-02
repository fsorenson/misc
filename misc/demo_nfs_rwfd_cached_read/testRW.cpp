#include <iostream>
#include <fstream>
#include <unistd.h>
#include <stdlib.h>
#include <bitset>
using namespace std;

int main (int argc, char **argv) {
    if (argc != 4) {
        cout << "testRW usage:\n"
             << "./testRW 2 0 filename  # Open file in RW mode, read from file\n"
             << "./testRW 2 1 filename  # Open file in RW mode, write to file\n"
             << "./testRW 2 2 filename  # Open file in RW mode" << endl;
        return 0;
    }

    int arg = atoi(argv[1]);
    int arg2 = atoi(argv[2]);

    std::ios_base::openmode op = fstream::in;
    cout << "I(" << std::bitset<8>(fstream::in) << ")\n"
         << "O(" << std::bitset<8>(fstream::out) << ")\n"
         << "A("<< std::bitset<8>(fstream::app) << ')' << endl;
    switch (arg) {
        case 1: op = fstream::out|fstream::app;   break;
        case 2: op |= fstream::out|fstream::app;  break;
    }

    fstream f(argv[3], op);
    if (f.is_open()) {
        cout << "Open file(" << std::bitset<8>(op) << ")" << endl;
        if (arg2 == 0) { // Read
            string line;
            while (getline(f,line)) {
                cout << line << '\n';
                sleep (1);
            }
        } else if (arg2 == 1) { // Write
            for (int i = 0; i < 100000; i++) {
                for (int j = 0; j < 20; j++)
                    f << j;
                f << endl;
                sleep(1);
            }
        } else {
            for (int i = 0; i < 100000; i++) {
                cout << "." << endl;
                sleep(1);
            }
        }
        f.close();
    } else {
        cout << "Unable to open file" << endl;
    }

    return 0;
}
