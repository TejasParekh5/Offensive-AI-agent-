#!/usr/bin/env python3
"""
GitHub Push Helper Script
Helps push the Cybersecurity Automation System to GitHub
"""

import subprocess
import sys
import os
from pathlib import Path

def run_command(command, description):
    """Run a command and handle errors."""
    print(f"📝 {description}")
    print(f"🔄 Running: {command}")
    
    try:
        result = subprocess.run(
            command, 
            shell=True, 
            capture_output=True, 
            text=True,
            cwd=Path(__file__).parent
        )
        
        if result.returncode == 0:
            print(f"✅ Success!")
            if result.stdout.strip():
                print(f"Output: {result.stdout.strip()}")
        else:
            print(f"❌ Error: {result.stderr.strip()}")
            return False
            
    except Exception as e:
        print(f"❌ Exception: {e}")
        return False
    
    print()
    return True

def check_git_auth():
    """Check if git authentication is set up."""
    print("🔑 Checking Git Authentication...")
    
    # Check if GitHub CLI is available
    try:
        result = subprocess.run(["gh", "auth", "status"], capture_output=True, text=True)
        if result.returncode == 0:
            print("✅ GitHub CLI authentication detected")
            return True
    except FileNotFoundError:
        pass
    
    # Check git config
    try:
        result = subprocess.run(["git", "config", "user.name"], capture_output=True, text=True)
        username = result.stdout.strip()
        
        result = subprocess.run(["git", "config", "user.email"], capture_output=True, text=True)
        email = result.stdout.strip()
        
        if username and email:
            print(f"✅ Git configured for: {username} ({email})")
            return True
        else:
            print("⚠️ Git user not configured")
            return False
    except:
        print("❌ Git not found")
        return False

def setup_git_config():
    """Set up git configuration."""
    print("⚙️ Setting up Git configuration...")
    
    username = input("Enter your GitHub username: ").strip()
    email = input("Enter your GitHub email: ").strip()
    
    if username and email:
        run_command(f'git config user.name "{username}"', "Setting Git username")
        run_command(f'git config user.email "{email}"', "Setting Git email")
        return True
    else:
        print("❌ Username and email required")
        return False

def main():
    """Main function to push to GitHub."""
    print("🚀 GitHub Push Helper for Cybersecurity Automation System")
    print("=" * 60)
    
    # Change to project directory
    project_dir = Path(__file__).parent
    os.chdir(project_dir)
    
    # Check current directory
    print(f"📁 Working directory: {os.getcwd()}")
    
    # Check if this is a git repository
    if not Path(".git").exists():
        print("❌ Not a git repository. Please run 'git init' first.")
        return False
    
    # Check git authentication
    if not check_git_auth():
        print("\n🔧 Git authentication setup required...")
        setup_git_config()
    
    # Check remote
    print("🔗 Checking remote repository...")
    result = subprocess.run(["git", "remote", "-v"], capture_output=True, text=True)
    if "github.com/TejasParekh5/Offensive-AI-agent-" not in result.stdout:
        print("⚙️ Adding GitHub remote...")
        run_command(
            "git remote add origin https://github.com/TejasParekh5/Offensive-AI-agent-.git",
            "Adding GitHub remote"
        )
    else:
        print("✅ GitHub remote already configured")
    
    # Check for changes
    print("📋 Checking for changes...")
    result = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True)
    
    if result.stdout.strip():
        print("📝 Uncommitted changes found. Adding and committing...")
        
        if not run_command("git add .", "Adding all files"):
            return False
            
        commit_message = input("Enter commit message (or press Enter for default): ").strip()
        if not commit_message:
            commit_message = "📊 Update cybersecurity automation system"
        
        if not run_command(f'git commit -m "{commit_message}"', "Committing changes"):
            return False
    else:
        print("✅ No uncommitted changes")
    
    # Get current branch
    result = subprocess.run(["git", "branch", "--show-current"], capture_output=True, text=True)
    current_branch = result.stdout.strip() or "main"
    
    # Push to GitHub
    print(f"🚀 Pushing to GitHub (branch: {current_branch})...")
    
    # First try simple push
    result = subprocess.run([
        "git", "push", "-u", "origin", current_branch
    ], capture_output=True, text=True)
    
    if result.returncode == 0:
        print("✅ Successfully pushed to GitHub!")
        print(f"🌐 Repository URL: https://github.com/TejasParekh5/Offensive-AI-agent-")
        return True
    else:
        print(f"❌ Push failed: {result.stderr}")
        
        # Provide helpful error messages
        if "authentication" in result.stderr.lower() or "permission" in result.stderr.lower():
            print("\n🔑 Authentication Error Solutions:")
            print("1. Use GitHub CLI: gh auth login")
            print("2. Use Personal Access Token:")
            print("   - Go to GitHub Settings > Developer settings > Personal access tokens")
            print("   - Generate new token with 'repo' permissions")
            print("   - Use token as password when prompted")
            print("3. Configure SSH keys (recommended for frequent use)")
            
        elif "repository not found" in result.stderr.lower():
            print("\n📂 Repository Error:")
            print("1. Make sure the repository exists on GitHub")
            print("2. Check the repository URL is correct")
            print("3. Ensure you have access to the repository")
            
        return False

if __name__ == "__main__":
    try:
        success = main()
        if success:
            print("\n🎉 GitHub push completed successfully!")
            print("Next steps:")
            print("1. Visit your repository: https://github.com/TejasParekh5/Offensive-AI-agent-")
            print("2. Add a description and topics to your repository")
            print("3. Consider adding GitHub Actions for CI/CD")
            print("4. Star your own repository to boost visibility! ⭐")
        else:
            print("\n❌ GitHub push failed. Please check the errors above.")
        
        input("\nPress Enter to exit...")
        
    except KeyboardInterrupt:
        print("\n\n⏹️ Operation cancelled by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        input("Press Enter to exit...")
