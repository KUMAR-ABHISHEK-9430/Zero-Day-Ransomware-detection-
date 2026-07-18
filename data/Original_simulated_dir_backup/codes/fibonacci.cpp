#include <iostream>
#include <vector>
#include <string>
#include <numeric>

// Struct representing a mathematical helper tool
struct MathTool {
    std::string name;
    int version;
};

// Function to calculate Fibonacci recursively
int fibonacci(int n) {
    if (n <= 1) return n;
    return fibonacci(n - 1) + fibonacci(n - 2);
}

// Function to calculate factorial recursively
long long factorial(int n) {
    if (n <= 1) return 1;
    return n * factorial(n - 1);
}

// Function to calculate Greatest Common Divisor (GCD)
int gcd(int a, int b) {
    while (b != 0) {
        int temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Function to compute average of a vector of doubles
double calculateAverage(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / values.size();
}

// Helper to print tool info
void printToolInfo(const MathTool& tool) {
    std::cout << "Tool: " << tool.name << " (v" << tool.version << ")" << std::endl;
}

int main() {
    MathTool tool{"AntiGravity Math Suite", 2};
    printToolInfo(tool);

    std::cout << "--- Math Operations Demo ---" << std::endl;
    
    // Demonstrate Fibonacci
    int fibNum = 10;
    std::cout << "Fibonacci of " << fibNum << " is: " << fibonacci(fibNum) << std::endl;

    // Demonstrate Factorial
    int factNum = 12;
    std::cout << "Factorial of " << factNum << " is: " << factorial(factNum) << std::endl;

    // Demonstrate GCD
    int a = 56, b = 98;
    std::cout << "GCD of " << a << " and " << b << " is: " << gcd(a, b) << std::endl;

    // Demonstrate Vector Averages
    std::vector<double> scores = {88.5, 92.0, 79.5, 95.0, 85.0, 91.5, 77.0, 84.0, 90.0, 93.5};
    std::cout << "Average test score: " << calculateAverage(scores) << std::endl;

    // Add some loops to expand execution representation
    std::cout << "Counting squares from 1 to 10:" << std::endl;
    for (int i = 1; i <= 10; ++i) {
        std::cout << i << "^2 = " << (i * i) << "  ";
    }
    std::cout << std::endl;

    std::cout << "Demonstrating a basic vector manipulation:" << std::endl;
    std::vector<int> numbers;
    for (int i = 0; i < 15; ++i) {
        numbers.push_back(i * 3);
    }
    for (int num : numbers) {
        if (num % 2 == 0) {
            std::cout << num << " (even) ";
        } else {
            std::cout << num << " (odd) ";
        }
    }
    std::cout << std::endl;

    std::cout << "Operations complete." << std::endl;
    return 0;
}
