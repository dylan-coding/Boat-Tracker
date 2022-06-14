# Boat Tracker

An implementation of Google Cloud Platform to track boats and loads.

## Description

This API provides functionality for tracking boats and the loads carried by
those boats. Boats are owned by users, who are authenticated with a gmail account.
Users can go to https://smithdyl-cs493-final.wl.r.appspot.com/ to register. Loads
are not owned by specific users, and can be freely modified by any authenticated users
provided the modification does not alter it's relationship with another user's boat.

## Getting Started

### Dependencies

#### For API access:
No dependencies to access API, gmail account needed to register.

#### Local run:
Flask v. 2.1.0
google-cloud-datastore v. 2.4.0

### Installing

If you choose to install the project on your own machine, you will need to setup a
Google Cloud Platform project at the file location containing the file main.py. Please
follow the steps outlined by Google Cloud Platform's documentation, as found here:
https://cloud.google.com/run/docs/setup

### Executing program

See the API specification document for details on how to use this API.

## Version History

* 0.1
    * Initial Release

## License

This project is licensed under the MIT License - see the LICENSE.md file for details

## Acknowledgments

Inspiration, code snippets, etc.
* Google Cloud Platform API Documentation
	* In particular: https://googleapis.dev/python/google-api-core/latest/auth.html