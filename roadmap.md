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
**GOAL:** _Refactor Structure_
 - [x] Add proper Log-Config for CLI
 - [x] Add Log Config for library
 - [x] Package the Project
 - [x] Refactor project to make it compatible for min 3.7+ (currently 3.8+)
 - [x] Refactor project structure
 - [x] Structure the Test Files better

Completed May 23rd 2020

:bookmark: Tag: [v0.3](https://github.com/JimFawkes/secret-loader/releases/tag/v0.3)

--------

## v0.4
**GOAL:** _Add documentation & Logs_
 - [x] Add proper documentation in SKLearn Style to all Code
 - [x] Add How-To for module
 - [x] Add How-To for CLI
 - [x] Add examples


Completed June 7th 2020

:bookmark: Tag: [v0.4](https://github.com/JimFawkes/secret-loader/releases/tag/v0.4)

--------

## v0.5
**GOAL:** _Package and Publish Project_
 - [x] Publish Package
 - [x] Update metadata


Completed June 7th 2020

:bookmark: Tag: [v0.5](https://github.com/JimFawkes/secret-loader/releases/tag/v0.5)

--------

# Backlog Potential Enhancements
 - [ ] Review/Refactor Tests
 - [ ] Add a Logo for the Project
 - [ ] Add Installation Guide to Readme
 - [ ] Add gifs to How-To
 - [ ] Allow Users to configure cli via config file (add multiple custom loaders, change priority)
 - [ ] Enable some results parser options for CLI
 - [ ] Add Google Cloud/Azure Loaders
 - [ ] Add parser selection to cli (e.g. construct db connection string from dict)
 - [ ] Allow to pass default values when retrieving secrets
 - [ ] Allow to fail silently when retrieving secrets
 - [ ] Make the secret name a positional argument in the cli instead of an optional one.
