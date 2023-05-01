#include <fstream>
#include <cstring>
#include <sstream>
#include <iostream>

// Function to write the sealed data to a file with identifier
bool write_seal_data(const uint8_t* sealed_data, size_t sealed_size, int identifier) {
    // Convert identifier to string
    std::ostringstream oss;
    oss << identifier;
    std::string identifier_str = oss.str();

    // Open file for writing
    std::ofstream outfile;
    outfile.open("seal_data.txt", std::ios_base::app);
    if (!outfile.is_open()) {
        std::cout << "Error: failed to open file for writing" << std::endl;
        return false;
    }

    outfile << "<" << identifier_str << ":";

    for(size_t i = 0; i< sealed_size; i++){
	    outfile <<(int)sealed_data[i] << " ";
    }

    // Write the identifier and sealed data to file
    outfile << ">" << std::endl;

    // Close the file
    outfile.close();

    return true;
}

// Function to read the sealed data from file based on identifier
bool read_seal_data(int identifier, uint8_t* sealed_data_array, size_t array_size) {
    // Convert identifier to string
    std::ostringstream oss;
    oss << identifier;
    std::string identifier_str = oss.str();

    // Open file for reading
    std::ifstream infile;
    infile.open("seal_data.txt");
    if (!infile.is_open()) {
        std::cout << "Error: failed to open file for reading" << std::endl;
        return false;
    }

    // Search for the identifier in the file
    std::string line;
    bool identifier_found = false;
    while (std::getline(infile, line)) {
        // Check if line contains the identifier
        if (line.find("<" + identifier_str + ":") != std::string::npos) {
            identifier_found = true;
            // Extract the sealed data from the line
            std::stringstream ss(line.substr(line.find(":")+1));
            int sealed_data;
            size_t index = 0;
            // Read integers from the line and store them in the sealed_data_array
            while (ss >> sealed_data && index < array_size) {
                sealed_data_array[index++] = sealed_data;
            }
            break;
        }
    }

    // Close the file
    infile.close();

    // Check if the identifier was found in the file
    if (!identifier_found) {
        std::cout << "Error: identifier not found in file" << std::endl;
        return false;
    }

    return true;
}