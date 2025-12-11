# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set the working directory in the container
WORKDIR /app

# Copy the current directory contents into the container at /app
COPY . /app

# Install bash
RUN apt-get update && apt-get install -y bash git nano
RUN pip install httpx
RUN pip install -e .

# Start bash by default
CMD ["crapsecrets","-u","http://localhost", "-r"]
