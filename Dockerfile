FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

# Install system dependencies
RUN apt-get update && apt-get install -y \
    cppcheck \
    python3 \
    python3-pip \
    universal-ctags \
    curl \
    unzip \
    git \
    build-essential \
    jq \
    && rm -rf /var/lib/apt/lists/*

# Install CodeQL CLI
RUN curl -L https://github.com/github/codeql-cli-binaries/releases/latest/download/codeql-linux64.zip -o codeql.zip \
    && unzip codeql.zip -d /opt/ \
    && rm codeql.zip \
    && ln -s /opt/codeql/codeql /usr/local/bin/codeql

# Clone CodeQL standard library
RUN git clone --depth 1 https://github.com/github/codeql.git /opt/codeql-repo

WORKDIR /app

# Copy application files
COPY pipeline/ ./pipeline/
COPY src/ ./src/
COPY datasets/ ./datasets/
COPY generate_critical_report.py ./

# Set executable permissions
RUN chmod +x /app/pipeline/static_scan.sh /app/pipeline/parse_reports.py /app/generate_critical_report.py

# Create artifacts directory
RUN mkdir -p /app/artifacts

# Set environment variables
ENV CODEQL_HOME=/opt/codeql
ENV PATH="${PATH}:/opt/codeql"

CMD ["/bin/bash"]
