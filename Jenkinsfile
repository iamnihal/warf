pipeline {
    agent any
    stages {
        stage('Gitleaks Running') {
            steps {
                sh 'gitleaks detect -v --log-opts="--all -1" --report-path="Gitleaks_Output.json"'
                sh 'description=$(jq .[].Description)'
                sh 'echo ${description}'
            }
        }
        
    }
    post {
        always {
            script {
                if (readFile("Gitleaks_Output.json").length() > 3) {
                    emailext (to: 'nihalchoudhary55@gmail.com', attachmentsPattern: 'Gitleaks_Output.json', subject: "[Alert] Secret Found in Job ${description} - '${env.JOB_NAME}' | Build - '${env.BUILD_NUMBER}' ", body: 'Hi Team! Secret Scanner found a secret in recent commit, Please check attached file for more information.', mimeType: 'text/html');
                }else {
                    emailext (to: 'nihalchoudhary55@gmail.com', subject: "No Secret Found in Job ${description} - '${env.JOB_NAME}' | Build - '${env.BUILD_NUMBER}' ", body: "Hi Team! There is no secret found in recent commit in Job - '${env.JOB_NAME}' | Build - '${env.BUILD_NUMBER}' :) .", mimeType: 'text/html');
                }
            }
        }
    }
}
