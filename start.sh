!/bin/bash

# Find all Python 3.x executables and sort them by version
PYTHON_EXEC=$(find /usr/bin -maxdepth 1 -regex ".*/python3\.[0-9]+" | \
              awk -F'python' '{print $2}' | \
              sort -t '.' -k1,1n -k2,2n | \
              tail -n 1)

# Check if a valid version was found
if [ -z "$PYTHON_EXEC" ]; then
    echo "No Python 3 version found. Please install Python 3."
    exit 1
else
    # Reconstruct the full path
    PYTHON_EXEC="/usr/bin/python${PYTHON_EXEC}"
    echo "Using Python executable: $PYTHON_EXEC"
fi

# Create a virtual environment named "venv"
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    $PYTHON_EXEC -m venv venv
else
    echo "Virtual environment already exists."
fi

# Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Export PYTHONPATH to include the current directory
export PYTHONPATH=$(pwd):$PYTHONPATH
echo "PYTHONPATH set to: $PYTHONPATH"

# Install dependencies if requirements.txt exists
if [ -f "requirements.txt" ]; then
    echo "Installing dependencies from requirements.txt..."
    pip install -r requirements.txt
	#pip install -r requirements.txt --trusted-host pypi.org --trusted-host pypi.python.org --trusted-host files.pythonhosted.org
else
    echo "No requirements.txt found. Skipping dependency installation."
fi

clear
echo "Environment setup complete. Virtual environment activated."
echo "Sample usage:"
echo "$PYTHON_EXEC ./crapsecrets/examples/cli.py -u https://catalog.update.microsoft.com/Search.aspx -r"
echo "$PYTHON_EXEC ./crapsecrets/examples/cli.py -u https://catalog.update.microsoft.com/Search.aspx -mrd 5"
echo "$PYTHON_EXEC ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -u https://catalog.update.microsoft.com/Search.aspx"
echo "$PYTHON_EXEC ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -mkf ./local/aspnet_machinekeys_local.txt -u https://catalog.update.microsoft.com/Search.aspx"
echo "$PYTHON_EXEC ./crapsecrets/examples/cli.py -mrd 5 -avsk -fvsp -mkf ./local/aspnet_machinekeys_local.txt -mkf ./crapsecrets/resources/aspnet_machinekeys.txt -u https://catalog.update.microsoft.com/Search.aspx"

# Keep the shell open with the virtual environment activated
exec "$SHELL"
