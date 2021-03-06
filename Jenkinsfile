pipeline {
    agent any
    stages {
        stage('Test') {
            agent { docker
            { image 'python:3.7.2'
            args '-u 0:0'}}
            steps {
                sh 'pip3 install --upgrade --requirement code/requirements.txt'
                sh 'cd code && flake8 .'
                sh 'cd code && coverage run --source api/ -m pytest --verbose tests/unit/ && coverage report'
            }
        }
        stage('Build') {
            steps {
                sh 'docker build -t tr-05-ibm-xforce-exchange .'
                sh 'docker run -d -p 9090:9090 --name tr-05-ibm-xforce-exchange tr-05-ibm-xforce-exchange'
                sh 'while true; do if docker logs tr-05-ibm-xforce-exchange | grep "entered RUNNING state"; then break; else sleep 1; fi done'
                sh 'curl -X POST -sSLi http://localhost:9090/health | grep "200 OK"'
                sh 'curl -X GET -sSLi http://localhost:9090/watchdog | grep "200 OK"'
            }
        }
    }
    post {
        always {
            sh 'docker kill tr-05-ibm-xforce-exchange && docker rm tr-05-ibm-xforce-exchange'
        }
    }
}