#!/bin/bash
# Script to verify code quality checks are passing
# Usage: ./verify_code_quality.sh [--fix]

set -e  # Exit on error

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if --fix flag is provided
FIX_MODE=false
if [ "$1" == "--fix" ] || [ "$1" == "-f" ]; then
    FIX_MODE=true
    echo -e "${YELLOW}=== Running in FIX mode ===${NC}"
    echo "Will automatically fix formatting issues"
else
    echo -e "${GREEN}=== Code Quality Verification ===${NC}"
    echo "Run with --fix flag to automatically fix issues"
fi
echo ""

# Function to run checks or fixes
run_quality_checks() {
    local fix=$1
    local all_passed=true
    
    if [ "$fix" = true ]; then
        # Fix mode - apply formatters
        echo -e "${YELLOW}1. Applying black formatting...${NC}"
        poetry run black rpc_helper/ tests/
        echo -e "${GREEN}✅ Black formatting applied${NC}"
        echo ""
        
        echo -e "${YELLOW}2. Fixing import sorting with isort...${NC}"
        poetry run isort rpc_helper/ tests/
        echo -e "${GREEN}✅ Import sorting fixed${NC}"
        echo ""
        
        echo -e "${YELLOW}3. Running flake8 to identify remaining issues...${NC}"
        if poetry run flake8 .; then
            echo -e "${GREEN}✅ No linting issues found${NC}"
        else
            echo -e "${YELLOW}⚠️  Some linting issues cannot be auto-fixed${NC}"
            echo "   Please review and fix manually"
            all_passed=false
        fi
    else
        # Check mode - verify without changing
        echo "1. Checking code formatting with black..."
        if poetry run black --check rpc_helper/ tests/; then
            echo -e "${GREEN}✅ Black check passed${NC}"
        else
            echo -e "${RED}❌ Black check failed${NC}"
            echo "   Run with --fix flag to auto-format"
            all_passed=false
        fi
        echo ""
        
        echo "2. Checking import sorting with isort..."
        if poetry run isort --check-only rpc_helper/ tests/; then
            echo -e "${GREEN}✅ Isort check passed${NC}"
        else
            echo -e "${RED}❌ Import sorting check failed${NC}"
            echo "   Run with --fix flag to auto-sort"
            all_passed=false
        fi
        echo ""
        
        echo "3. Running flake8 linting..."
        if poetry run flake8 .; then
            echo -e "${GREEN}✅ Flake8 check passed${NC}"
        else
            echo -e "${RED}❌ Flake8 check failed${NC}"
            echo "   Review errors above and fix manually"
            all_passed=false
        fi
    fi
    
    echo ""
    return $([ "$all_passed" = true ] && echo 0 || echo 1)
}

# Main execution
echo "Ensuring poetry dependencies are installed..."
poetry install --quiet

echo ""
if run_quality_checks $FIX_MODE; then
    if [ "$FIX_MODE" = true ]; then
        echo -e "${GREEN}=== All fixes applied successfully ===${NC}"
        echo ""
        echo "Next steps:"
        echo "1. Review the changes: git diff"
        echo "2. Stage the changes: git add ."
        echo "3. Commit with a message: git commit -m 'Apply code formatting'"
    else
        echo -e "${GREEN}=== All quality checks passed ===${NC}"
        echo ""
        echo "Your code is ready to commit!"
    fi
    exit 0
else
    if [ "$FIX_MODE" = false ]; then
        echo -e "${RED}=== Some quality checks failed ===${NC}"
        echo ""
        echo "To automatically fix formatting issues, run:"
        echo "  ./scripts/verify_code_quality.sh --fix"
        echo ""
        echo "Or fix individually:"
        echo "  poetry run black rpc_helper/ tests/"
        echo "  poetry run isort rpc_helper/ tests/"
        exit 1
    else
        echo -e "${YELLOW}=== Some issues require manual attention ===${NC}"
        echo ""
        echo "Please review the flake8 errors above and fix them manually."
        exit 1
    fi
fi