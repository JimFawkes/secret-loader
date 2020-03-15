# Versions Roadmap
What needs to be completed for the next version number.
Define goals and todos for that version.

## v0.1
**GOAL:** _Write Core Functionality_
 - [x] Add Secret Loader Machinery
 - [x] Add Env Variable Loader
 - [x] Add Env File Loader
 - [x] Add AWS SecretsManager SecretLoader
 - [x] Have >95% Test Coverage

Completed March 13th 2020

:bookmark: Tag: [v0.1](https://github.com/JimFawkes/secret-loader/releases/tag/v0.1)

--------

## v0.2
**GOAL:** _Add CLI to load secrets_
 - [x] Allow secrets to be retrieved for all or a specific Loader
 - [x] Add option to add custom loader with specific priority
 - [x] Add custom loader without removing pre-registered loaders
 - [x] Add option to list all registered loaders with their priority
 - [x] Find a way to easily inlcude Custom 3rd Party Loaders
 - [x] Add proper Help message

Completed March 15th 2020

:bookmark: Tag: [v0.2](https://github.com/JimFawkes/secret-loader/releases/tag/v0.2)

--------

## v0.3
**GOAL:** _Add documentation & Logs_
 - [ ] Add proper documentation in SKLearn Style to all Code
 - [ ] Add Installation Guide to Readme
 - [ ] Add How-To for module
 - [ ] Add How-To for CLI
 - [ ] Add examples
 - [ ] Add gifs to How-To
 - [ ] Add proper Log-Config for CLI
 - [ ] Add Log Config for library

_Completed Date and version tag link_

--------

## v0.4
**GOAL:** _Refactor Tests & Add tox_
 - [ ] Remove all unnecessary tests
 - [ ] Structure the Test Files better
 - [ ] Refactor project to make it compatible for min 3.7+ (currently 3.8+)
 - [ ] Use tox to test for all supported python versions

_Completed Date and version tag link_

--------

## v1.0
**GOAL:** _Package and Publish Project_
 - [ ] Package the Project
 - [ ] Add a Logo for the Project

_Completed Date and version tag link_

--------

# Backlog Potential Enhancements
 - [ ] Allow Users to configure cli via config file (add multiple custom loaders, change priority)
 - [ ] Enable some results parser options for CLI
