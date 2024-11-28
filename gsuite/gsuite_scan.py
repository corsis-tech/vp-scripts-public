import os
import json
import sys
import subprocess
import shutil
from google.oauth2 import service_account
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
import tempfile
import time
import pickle
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
import socket
import webbrowser
from http.server import HTTPServer, BaseHTTPRequestHandler
import urllib.parse
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description='Run Google Workspace security scan')
    parser.add_argument(
        '--customer-id',
        help='Google Workspace Customer ID',
        required=True
    )
    parser.add_argument(
        '--subject-email',
        help='Google Workspace subject email to use for scanning',
        required=True
    )
    parser.add_argument(
        '--output-dir',
        help='Directory for scan results',
        default='scubagoggles_output'
    )
    return parser.parse_args()

def is_port_in_use(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex(('localhost', port)) == 0

def find_available_port(start=8080, end=8100):
    for port in range(start, end):
        if not is_port_in_use(port):
            return port
    raise RuntimeError("No available ports found")

class ScubaGogglesAutomation:
    def __init__(self, customer_id, admin_email, output_dir):
        self.customer_id = customer_id
        self.admin_email = admin_email
        self.output_dir = os.path.abspath(output_dir)
        self.project_id = 'workspace-scan-' + str(int(time.time()))

        os.makedirs(self.output_dir, exist_ok=True)

        self.base_dir = os.path.join(os.getcwd(), 'workspace_scan')
        os.makedirs(self.base_dir, exist_ok=True)

        self.service_account_key_path = os.path.join(self.base_dir, 'service-account-key.json')
        self.scubagoggles_dir = os.path.join(self.base_dir, 'ScubaGoggles')
        self.creds = None



    def authenticate_user(self):
        """Authenticate user using OAuth flow"""
        print("Initiating user authentication...")

        SCOPES = [
            'https://www.googleapis.com/auth/cloud-platform',
            'https://www.googleapis.com/auth/cloudplatformprojects',
            'https://www.googleapis.com/auth/admin.directory.customer.readonly',
            'https://www.googleapis.com/auth/admin.directory.domain.readonly'
        ]

        print("""
Please follow these steps before continuing:
1. Go to https://console.cloud.google.com/apis/credentials
2. Create a new project or select an existing one
3. Click 'Create Credentials' -> 'OAuth client ID'
4. Choose 'Desktop app' as application type
5. Give it a name (e.g., 'ScubaGoggles Automation')
6. Download the client configuration file
7. Save it as 'client_secrets.json' in the same directory as this script
        """)

        input("Press Enter once you've completed these steps...")

        if not os.path.exists('client_secrets.json'):
            raise FileNotFoundError("client_secrets.json not found. Please follow the setup instructions.")

        creds = None
        if os.path.exists('token.pickle'):
            with open('token.pickle', 'rb') as token:
                creds = pickle.load(token)

        if not creds or not creds.valid:
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(Request())
            else:
                port = find_available_port()

                flow = InstalledAppFlow.from_client_secrets_file(
                    'client_secrets.json',
                    SCOPES,
                    redirect_uri=f'http://localhost:{port}'
                )

                creds = flow.run_local_server(port=port)

            with open('token.pickle', 'wb') as token:
                pickle.dump(creds, token)

        self.creds = creds
        print("Authentication successful!")
        return creds

    def wait_for_api_enable(self, service_usage, api_name, max_retries=5, delay=10):
        """Wait for an API to be fully enabled"""
        print(f"Waiting for {api_name} to be fully enabled...")
        
        for attempt in range(max_retries):
            try:
                service = service_usage.services().get(
                    name=f'projects/{self.project_id}/services/{api_name}'
                ).execute()
                
                if service.get('state') == 'ENABLED':
                    print(f"✓ {api_name} is enabled")
                    return True
                else:
                    print(f"API not yet enabled, attempt {attempt + 1}/{max_retries}")
                    time.sleep(delay)
            except Exception as e:
                print(f"Error checking API status: {str(e)}")
                time.sleep(delay)
        
        return False
    
    def enable_api_in_project(self, service_usage, project_id, api_name, max_retries=5):
        print(f"Enabling {api_name} in project {project_id}...")
        
        try:
            operation = service_usage.services().enable(
                name=f'projects/{project_id}/services/{api_name}'
            ).execute()
            
            for attempt in range(max_retries):
                try:
                    service = service_usage.services().get(
                        name=f'projects/{project_id}/services/{api_name}'
                    ).execute()
                    
                    if service.get('state') == 'ENABLED':
                        print(f"✓ {api_name} is enabled in project {project_id}")
                        return True
                    else:
                        print(f"Waiting for API to be enabled... (attempt {attempt + 1}/{max_retries})")
                        time.sleep(10)
                except Exception as e:
                    print(f"Error checking API status: {str(e)}")
                    time.sleep(10)
            
            return False
        except Exception as e:
            print(f"Error enabling {api_name}: {str(e)}")
            return False
    
    def setup_prerequisites(self):
        print("Setting up prerequisites...")
        
        try:
            parent_project = self.creds._project_id
            print(f"Parent project ID: {parent_project}")
        except:
            parent_project = input("Please enter your parent project ID (from the error message): ")
        
        print("\nEnabling necessary APIs in parent project...")
        service_usage = build('serviceusage', 'v1', credentials=self.creds)
        parent_apis = [
            'serviceusage.googleapis.com',
            'cloudresourcemanager.googleapis.com',
            'iam.googleapis.com'
        ]
        
        for api in parent_apis:
            if not self.enable_api_in_project(service_usage, parent_project, api):
                print(f"\nPlease enable {api} manually at:")
                print(f"https://console.cloud.google.com/apis/library/{api}?project={parent_project}")
                input("Press Enter once you've enabled the API...")
        
        print("\nCreating new Google Cloud project...")
        cloudresourcemanager = build('cloudresourcemanager', 'v1', credentials=self.creds)
        project_body = {
            'projectId': self.project_id,
            'name': 'Workspace Security Scan'
        }
        project = cloudresourcemanager.projects().create(body=project_body).execute()
        
        print("Waiting for project creation to propagate...")
        time.sleep(30)
        
        print("\nEnabling APIs in new project...")
        new_project_apis = [
            'serviceusage.googleapis.com',
            'cloudresourcemanager.googleapis.com',
            'iam.googleapis.com',
            'admin.googleapis.com',
            'groupssettings.googleapis.com'
        ]
        
        for api in new_project_apis:
            if not self.enable_api_in_project(service_usage, self.project_id, api):
                print(f"\nPlease enable {api} manually at:")
                print(f"https://console.cloud.google.com/apis/library/{api}?project={self.project_id}")
                input("Press Enter once you've enabled the API...")
        
        print("\nWaiting for all API enablements to propagate...")
        time.sleep(30)
        
        return self.setup_service_account()
    
    def setup_service_account(self):
        print("\nCreating service account...")
        iam = build('iam', 'v1', credentials=self.creds)
        
        try:
            service_account_body = {
                'accountId': 'workspace-scan',
                'serviceAccount': {
                    'displayName': 'Workspace Security Scan Service Account'
                }
            }
            
            print("Creating service account...")
            service_account = iam.projects().serviceAccounts().create(
                name=f'projects/{self.project_id}',
                body=service_account_body
            ).execute()
            
            print("Waiting for service account creation to propagate...")
            time.sleep(10)
            
            service_account_email = service_account.get('email')
            if not service_account_email:
                service_account_email = f'workspace-scan@{self.project_id}.iam.gserviceaccount.com'
            
            print("Creating service account key...")
            key = iam.projects().serviceAccounts().keys().create(
                name=f'projects/{self.project_id}/serviceAccounts/{service_account_email}',
                body={'privateKeyType': 'TYPE_GOOGLE_CREDENTIALS_FILE'}
            ).execute()
            
            print("Processing key data...")
            if isinstance(key, dict) and 'privateKeyData' in key:
                try:
                    import base64
                    key_data = base64.b64decode(key['privateKeyData']).decode('utf-8')
                    key_json = json.loads(key_data)
                    
                    with open(self.service_account_key_path, 'w') as f:
                        json.dump(key_json, f, indent=2)
                    print(f"Service account key saved to {self.service_account_key_path}")
                except Exception as e:
                    print(f"Error processing key data: {str(e)}")
                    raise
            else:
                print("Unexpected key format:", key)
                raise ValueError("Invalid key response format")
            
            # Define required scopes
            self.scopes = [
                    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
                    "https://www.googleapis.com/auth/admin.directory.domain.readonly",
                    "https://www.googleapis.com/auth/admin.directory.group.readonly",
                    "https://www.googleapis.com/auth/admin.directory.orgunit.readonly",
                    "https://www.googleapis.com/auth/admin.directory.user.readonly",
                    "https://www.googleapis.com/auth/apps.groups.settings"
            ]
           
            # Provide instructions for manual domain-wide delegation setup
            print("\nDomain-wide delegation must be configured manually.")
            print("\nPlease follow these steps:")
            print("1. Go to admin.google.com > Security > API Controls > Domain-wide Delegation")
            print("2. Click 'Add new'")
            print(f"3. Enter the Client ID: {service_account['uniqueId']}")
            print("4. Add the following OAuth scopes (copy and paste the entire list):")
            print("\n".join(self.scopes))
            print("\nIMPORTANT: Make sure to include all scopes exactly as shown above.")
            
            input("\nPress Enter once you've completed the domain-wide delegation setup...")
            print("\nProceeding with service account configuration complete.")
            
            return service_account_email
            
        except Exception as e:
            print(f"Error in service account setup: {str(e)}")
            if hasattr(e, 'content'):
                print(f"Response content: {e.content}")
            if hasattr(e, 'resp'):
                print(f"Status code: {e.resp.status}")
            raise

    def clone_scubagoggles(self):
        print("\nSetting up ScubaGoggles...")

        if os.path.exists(self.scubagoggles_dir):
            print("Removing existing ScubaGoggles directory...")
            shutil.rmtree(self.scubagoggles_dir)

        print("Cloning ScubaGoggles repository...")
        try:
            subprocess.run([
                'git', 'clone',
                'https://github.com/cisagov/ScubaGoggles.git',
                self.scubagoggles_dir
            ], check=True)
            print("ScubaGoggles cloned successfully")
        except subprocess.CalledProcessError as e:
            print(f"Error cloning ScubaGoggles: {str(e)}")
            raise

    def download_opa(self):
        print("\nDownloading OPA executable...")
    
        try:
            if sys.platform == "darwin":
                os_type = "macos"
                opa_executable = "opa_darwin_amd64"
            elif sys.platform == "win32":
                os_type = "windows"
                opa_executable = "opa_windows_amd64.exe"
            else:
                os_type = "linux"
                opa_executable = "opa_linux_amd64_static"
    
            download_script = os.path.join(self.scubagoggles_dir, 'download_opa.py')
            if not os.path.exists(download_script):
                raise Exception(f"download_opa.py not found at {download_script}")
    
            result = subprocess.run([
                'python3', download_script,
                '-os', os_type
            ], cwd=self.scubagoggles_dir, check=True, capture_output=True, text=True)
    
            print(result.stdout)
            if result.stderr:
                print("Warnings during OPA download:")
                print(result.stderr)
    
            # Make OPA executable
            if os_type != "windows":  # Skip for Windows
                opa_path = os.path.join(self.scubagoggles_dir, opa_executable)
                if os.path.exists(opa_path):
                    print(f"Setting executable permissions for {opa_executable}...")
                    os.chmod(opa_path, 0o755)  # rwxr-xr-x permissions
                    print("Executable permissions set successfully")
                else:
                    raise Exception(f"OPA executable not found at {opa_path}")
    
            print("OPA executable downloaded and configured successfully")
    
        except subprocess.CalledProcessError as e:
            print(f"Error downloading OPA:")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            raise
        except Exception as e:
            print(f"Error in OPA download process: {str(e)}")
            raise

    def run_scan(self, service_account_email):
        print("\nPreparing to run ScubaGoggles scan...")
        
        try:
            scuba_script = os.path.join(self.scubagoggles_dir, 'scuba.py')
            if not os.path.exists(scuba_script):
                raise Exception(f"scuba.py not found at {scuba_script}")
            
            self.download_opa()
            
            print("\nRunning ScubaGoggles scan...")
            print(f"Working directory: {self.scubagoggles_dir}")
            print(f"Service account key path: {self.service_account_key_path}")
            print(f"Output directory: {self.output_dir}")
            print(f"Using subject email: {self.subject_email}")
            
            # Run the scan with provided subject email
            result = subprocess.run([
                'python3', scuba_script,
                'gws',  # Google Workspace scan
                '--customer', self.customer_id,
                '--subjectemail', self.subject_email,  # Use provided subject email
                '-c', self.service_account_key_path,
                '-o', self.output_dir,
                '--debug'
            ], cwd=self.scubagoggles_dir, check=True, capture_output=True, text=True)
            
            print(result.stdout)
            if result.stderr:
                print("Warnings during scan:")
                print(result.stderr)
                
            print(f"\nScan completed successfully!")
            print(f"Results are available in: {self.output_dir}")
            
        except subprocess.CalledProcessError as e:
            print(f"Error during scan process:")
            print(f"Return code: {e.returncode}")
            print(f"stdout: {e.stdout}")
            print(f"stderr: {e.stderr}")
            raise
        except Exception as e:
            print(f"Unexpected error: {str(e)}")
            raise

    
    def run(self):
        try:
            self.authenticate_user()
            service_account_email = self.setup_prerequisites()
            self.clone_scubagoggles()
            self.run_scan(service_account_email)
        finally:
            self.cleanup()



    def cleanup(self):
        print("\nCleaning up resources...")

        try:
            # Delete project
            if self.creds:
                cloudresourcemanager = build('cloudresourcemanager', 'v1', credentials=self.creds)
                cloudresourcemanager.projects().delete(
                    projectId=self.project_id
                ).execute()
                print(f"Project {self.project_id} deleted successfully")
        except Exception as e:
            print(f"Warning: Project deletion failed: {str(e)}")

        try:
            if os.path.exists(self.service_account_key_path):
                os.remove(self.service_account_key_path)
                print("Service account key removed")

            if os.path.exists(self.scubagoggles_dir):
                shutil.rmtree(self.scubagoggles_dir)
                print("ScubaGoggles directory cleaned up")

        except Exception as e:
            print(f"Warning: Error during cleanup: {str(e)}")

        if os.path.exists('token.pickle'):
            os.remove('token.pickle')
            print("Credentials removed")


def main():
    args = parse_args()

    print(f"\nStarting ScubaGoggles automation:")
    print(f"Customer ID: {args.customer_id}")
    print(f"Admin Email: {args.subject_email}")
    print(f"Output Directory: {args.output_dir}")

    automation = ScubaGogglesAutomation(
        customer_id=args.customer_id,
        admin_email=args.subject_email,
        output_dir=args.output_dir
    )
    automation.run()


if __name__ == "__main__":
    main()
