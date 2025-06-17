#!/bin/bash

# File Encryptor Test Runner
# This script runs all tests and provides a comprehensive test report

echo "🧪 File Encryptor Test Suite"
echo "============================"
echo ""

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    local status=$1
    local message=$2
    case $status in
        "PASS")
            echo -e "${GREEN}✓ PASS${NC} $message"
            ;;
        "FAIL")
            echo -e "${RED}✗ FAIL${NC} $message"
            ;;
        "INFO")
            echo -e "${BLUE}ℹ INFO${NC} $message"
            ;;
        "WARN")
            echo -e "${YELLOW}⚠ WARN${NC} $message"
            ;;
    esac
}

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_status "FAIL" "Go is not installed or not in PATH"
    exit 1
fi

print_status "INFO" "Go version: $(go version)"
echo ""

# Clean up any previous test artifacts
print_status "INFO" "Cleaning up previous test artifacts..."
rm -f test_*.txt test_*.enc test_*.key test_*.pem test_*.yaml 2>/dev/null
rm -f key_*.key key_*.pub 2>/dev/null

# Run tests for each module
modules=(
    "cmd/file-encryptor"
    "pkg/logging"
)

total_tests=0
passed_tests=0
failed_tests=0

for module in "${modules[@]}"; do
    echo ""
    print_status "INFO" "Running tests for $module..."
    echo "----------------------------------------"
    
    # Run tests with verbose output and capture results
    if go test -v "./$module" 2>&1; then
        print_status "PASS" "$module tests completed successfully"
        # Count tests (this is a simple approximation)
        test_count=$(go test -v "./$module" 2>&1 | grep -c "=== RUN")
        total_tests=$((total_tests + test_count))
        passed_tests=$((passed_tests + test_count))
    else
        print_status "FAIL" "$module tests failed"
        test_count=$(go test -v "./$module" 2>&1 | grep -c "=== RUN")
        total_tests=$((total_tests + test_count))
        failed_count=$(go test -v "./$module" 2>&1 | grep -c "FAIL:")
        failed_tests=$((failed_tests + failed_count))
        passed_tests=$((passed_tests + test_count - failed_count))
    fi
done

echo ""
echo "🏁 Test Summary"
echo "==============="
print_status "INFO" "Total tests: $total_tests"
print_status "PASS" "Passed: $passed_tests"
if [ $failed_tests -gt 0 ]; then
    print_status "FAIL" "Failed: $failed_tests"
else
    print_status "PASS" "Failed: $failed_tests"
fi

# Calculate success rate
if [ $total_tests -gt 0 ]; then
    success_rate=$((passed_tests * 100 / total_tests))
    print_status "INFO" "Success rate: ${success_rate}%"
fi

echo ""

# Run test coverage analysis
print_status "INFO" "Generating test coverage report..."
echo "----------------------------------------"

# Generate coverage for each module
for module in "${modules[@]}"; do
    coverage_file="${module//\//_}_coverage.out"
    if go test -coverprofile="$coverage_file" "./$module" > /dev/null 2>&1; then
        coverage=$(go tool cover -func="$coverage_file" | tail -1 | awk '{print $3}')
        print_status "INFO" "$module coverage: $coverage"
        rm -f "$coverage_file"
    else
        print_status "WARN" "Could not generate coverage for $module"
    fi
done

echo ""

# Run benchmarks if available
print_status "INFO" "Running benchmarks..."
echo "----------------------------------------"
for module in "${modules[@]}"; do
    if go test -bench=. "./$module" > /dev/null 2>&1; then
        print_status "INFO" "Benchmarks available for $module"
        go test -bench=. "./$module"
    else
        print_status "INFO" "No benchmarks found for $module"
    fi
done

echo ""

# Test the built binary
print_status "INFO" "Testing built binary..."
echo "----------------------------------------"

if [ -f "./file-encryptor" ]; then
    # Test help command
    if ./file-encryptor --help > /dev/null 2>&1; then
        print_status "PASS" "Binary help command works"
    else
        print_status "FAIL" "Binary help command failed"
    fi
    
    # Test show-config command
    if ./file-encryptor --show-config > /dev/null 2>&1; then
        print_status "PASS" "Binary show-config command works"
    else
        print_status "FAIL" "Binary show-config command failed"
    fi
    
    # Test version command
    if ./file-encryptor --version > /dev/null 2>&1; then
        print_status "PASS" "Binary version command works"
    else
        print_status "FAIL" "Binary version command failed"
    fi
else
    print_status "WARN" "Binary not found. Run 'go build' first to test the binary."
fi

echo ""

# Clean up test artifacts
print_status "INFO" "Cleaning up test artifacts..."
rm -f test_*.txt test_*.enc test_*.key test_*.pem test_*.yaml 2>/dev/null
rm -f key_*.key key_*.pub 2>/dev/null

echo ""

# Final status
if [ $failed_tests -eq 0 ]; then
    print_status "PASS" "All tests completed successfully! 🎉"
    echo ""
    echo "✨ Your file-encryptor project is ready for production!"
    echo ""
    echo "Next steps:"
    echo "  1. Run 'go build -o file-encryptor cmd/file-encryptor/*.go' to build"
    echo "  2. Try './file-encryptor --help' to see all options"
    echo "  3. Test with './file-encryptor --show-config' to see configuration"
    echo ""
    exit 0
else
    print_status "FAIL" "Some tests failed. Please review the output above."
    exit 1
fi
