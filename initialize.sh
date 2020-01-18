#!/bin/bash

ask_for_input () {
	# Get User input to setup the new project
	read -p "Project Name: " project_name
	export PROJECT_NAME=$project_name
}

update_project_name () {
	# Search entire project for the template_project_name and replace with
	# actual project name
	echo "Update Project name in files for $PROJECT_NAME"
	rg python-template -g '!.git/*' -g '!initialize.sh' --hidden --files-with-matches  | xargs sed -i.bak "s/python-template/$PROJECT_NAME/g"
}

create_project_structure () {
	# Create the following directories:
	# - data
	# - logs
	# - tests (+init)
	# - project_name (+init)
	echo "Create Project Structure for $PROJECT_NAME"
	mkdir data logs tests $PROJECT_NAME
	touch tests/__init__.py $PROJECT_NAME/__init__.py
}

# TODO: Checkin changes to VCS

main () {
	echo "Initialize new project"
	ask_for_input
	update_project_name
	create_project_structure
}

main

