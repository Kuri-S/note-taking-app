# Use the official Go image as the base image
FROM golang:latest

# Set the working directory inside the container
WORKDIR /app

# Copy the entire project directory into the container
COPY . .

# Build the Go application inside the container
RUN go build -o main .

# Expose port 8080 for the application
#EXPOSE 8080

# Set the command to run when the container starts
CMD ["./main"]
