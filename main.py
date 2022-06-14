from flask import Flask, request, render_template, redirect, session, \
    make_response
from google.cloud import datastore
import requests
import json
import constants
# To generate random state
import random
import string

client = datastore.Client()
app = Flask(__name__)
app.secret_key = 'Very secure secret key'


@app.route('/')
def root():
    # Display root page
    return render_template('index.html')


@app.route('/login/')
def get_login():
    """
    Creates and stores a random state to authenticate user and redirects to
    login to Google
    """
    # Generate random state
    letters = string.ascii_letters + string.digits
    rand = ''.join(random.choice(letters) for i in range(13))
    # Upload state to datastore for later verification
    new_state = datastore.entity.Entity(key=client.key('state'))
    new_state.update({'state': rand})
    client.put(new_state)
    # Store state in current session 'state' value for verification
    session['state'] = rand
    # Send user to Google for login credentials
    return redirect(generate_redirect(rand), code=200)


def generate_redirect(rand):
    """
    Generates redirect url for user to supply login credentials for Google
    """
    # Append components of redirect url, keep separate for easy modification
    url = 'https://accounts.google.com/o/oauth2/v2/auth?'
    res_type = 'response_type=code'
    scope = '&scope=https://www.googleapis.com/auth/userinfo.profile'
    # Append random state to '&' to complete url component
    state = '&' + rand
    client_id = '&client_id=815193087543-rfijh6suv65am691ieltmpm2m4m3in24' \
                '.apps.googleusercontent.com'
    redirect_uri = '&redirect_uri=https://smithdyl-cs493-final.wl.r.' \
                   'appspot.com/oauth'
    return url + res_type + scope + state + client_id + redirect_uri


@app.route('/oauth/')
def display_credentials():
    """
    Authenticates user by checking session state against state saved to the
    datastore and displays their credentials
    """
    # Get session state
    session_state = session['state']
    # Get state from datastore
    query = client.query(kind='state')
    results = list(query.fetch())
    state_id = results[0].key.id
    state = results[0]['state']
    # Compare state values to authenticate user
    if session_state == state:
        sub, code = make_request(state_id)
        # Check currently registered users
        register_user(sub)
        # Display user's ID and JWT
        return '<p>Your user ID is: {}</p>' \
               '<p>Your JWT is: {}</p>'.format(sub, code)
    else:
        # Session state and state value from datastore do not match
        return '<p>Security Breach - The received value of State does not ' \
               'match the session state!</p>'


def register_user(sub):
    """
    Checks if user has been previously registered during login process,
    registering them if necessary
    """
    query = client.query(kind=constants.users)
    results = list(query.fetch())
    user_ids = []
    for item in results:
        # Add all user id's to array for searching
        user_ids.append(item['user_id'])
    if sub not in user_ids:
        # User has not previously registered, add sub value to datastore
        new_user = datastore.entity.Entity(key=client.key(constants.users))
        new_user.update({'user_id': sub})
        client.put(new_user)
    

def make_request(state_id):
    """
    Makes requests to Google APIs to get user's JWT
    """
    # Get access code from redirection request
    code = request.values.get('code')
    # Fill data payload
    data, headers = generate_payload(code)
    # Send access code as post request to receive token
    req = requests.post('https://oauth2.googleapis.com/token',
                        headers=headers, data=data)
    # Retrieve access token from response
    code = req.json()['id_token']
    req = requests.get('https://oauth2.googleapis.com/tokeninfo?id_token=' +
                       code)
    # Decode JWT and get sub
    sub = req.json()['sub']
    # Delete state from datastore to clear for future use
    state_key = client.key('state', int(state_id))
    key = client.get(key=state_key)
    client.delete(key)
    return sub, code
    

def generate_payload(code):
    """
    Generate the data and headers for the payload
    """
    data = {"code": str(code),
            "client_id": "815193087543-rfijh6suv65am691ieltmpm2m4m3in24.apps"
                         ".googleusercontent.com",
            "client_secret": "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",
            "redirect_uri": "https://smithdyl-cs493-final.wl.r.appspot.com/oauth",
            "grant_type": "authorization_code"}
    headers = {'content-type': 'application/x-www-form-urlencoded',
               'access_type': 'offline'}
    return data, headers


def validate_jwt():
    """
    Validates the user's JWT, returning their sub value as the user id if
    authenticated, or None if the user can't be authenticated
    """
    try:
        # Retrieve JWT from header's 'Authorization' field
        auth = request.headers['Authorization'][7:]
        req = requests.get(
            'https://oauth2.googleapis.com/tokeninfo?id_token=' + auth)
        # Decode token and get sub
        sub = req.json()['sub']
        return sub
    except:
        return None


@app.route('/users', methods=['GET'])
def users_read():
    """
    Route for displaying users currently registered with the API
    """
    if request.method == 'GET':
        query = client.query(kind=constants.users)
        results = list(query.fetch())
        return json.dumps(results), 200
    else:
        return 'Method not recognized', 405


@app.route('/boats', methods=['POST', 'GET'])
def boats_create_read():
    """
    Route for POST and GET requests for boats, returning GETS via pagination
    """
    if request.method == 'POST':
        if request.is_json is False:
            # Request object not a JSON
            error = {'Error': 'The request object must be a JSON file'}
            return json.dumps(error), 415
        content = request.get_json()
        # Validate user's credentials
        sub = validate_jwt()
        if sub is None:
            error = {'Error': 'Missing or invalid JWT'}
            return json.dumps(error), 401
        return post('boats', content, sub)
    elif request.method == 'GET':
        # Validate user's credentials
        sub = validate_jwt()
        if sub is None:
            error = {'Error': 'Missing or invalid JWT'}
            return json.dumps(error), 401
        return get_entity('boats', sub)
    else:
        return 'Method not recognized', 405


@app.route('/boats/<boat_id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def boats_update_delete(boat_id):
    """
    Route for DELETE, PUT, and PATCH methods for boats
    """
    # Validate user's credentials
    sub = validate_jwt()
    if sub is None:
        error = {'Error': 'Missing or invalid JWT'}
        return json.dumps(error), 401
    if request.method == 'DELETE':
        return delete('boats', boat_id, sub)
    elif request.method == 'GET':
        return get_boat(boat_id, sub)
    elif request.method == 'PUT' or request.method == 'PATCH':
        if request.is_json is False:
            # Request object not a JSON
            error = {'Error': 'The request object must be a JSON file'}
            return json.dumps(error), 415
        content = request.get_json()
        return put_patch('boats', request.method, content, boat_id, sub)
    else:
        return 'Method not recognized', 405
    

@app.route('/loads', methods=['POST', 'GET'])
def loads_create_read():
    """
    Route for POST and GET requests for loads, returning GETS via pagination
    """
    if request.method == 'POST':
        if request.is_json is False:
            # Request object not a JSON
            error = {'Error': 'The request object must be a JSON file'}
            return json.dumps(error), 415
        content = request.get_json()
        return post('loads', content)
    elif request.method == 'GET':
        return get_entity('loads')
    else:
        return 'Method not recognized', 405


@app.route('/loads/<load_id>', methods=['DELETE', 'GET', 'PUT', 'PATCH'])
def loads_update_delete(load_id):
    """
    Route for DELETE, PUT, and PATCH methods for loads
    """
    if request.method == 'DELETE':
        return delete('loads', load_id)
    elif request.method == 'GET':
        return get_load(load_id)
    elif request.method == 'PUT' or request.method == 'PATCH':
        content = request.get_json()
        return put_patch('loads', request.method, content, load_id)
    else:
        return 'Method not recognized', 405
    
    
@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def loads_put_delete_boats(boat_id, load_id):
    """
    Route for placing loads on, and removing them from, boats
    """
    # Validate user's credentials
    sub = validate_jwt()
    if sub is None:
        error = {'Error': 'Missing or invalid JWT'}
        return json.dumps(error), 401
    if request.method == 'PUT' or request.method == 'DELETE':
        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)
        if boat is None or boat['owner'] != 'auth0|' + str(sub):
            # Boat doesn't exist, return error to user
            error = {'Error': 'No boat with this boat_id exists for the '
                              'owner of the supplied JWT'}
            return json.dumps(error), 403
        if request.method == 'PUT':
            if load is None:
                # Load doesn't exist, return error to user
                error = {'Error': 'No load with this load_id exists'}
                return json.dumps(error), 404
            if load['carrier'] is None:
                load['carrier'] = boat['id']
                boat['loads'].append(load['id'])
                client.put(load)
                client.put(boat)
            elif load['carrier'] != boat['id']:
                remove_key = client.key(constants.boats, load['carrier'])
                remove = client.get(key=remove_key)
                remove['loads'].remove(load['id'])
                boat['loads'].append(load['id'])
                load['carrier'] = boat['id']
                client.put(remove)
                client.put(load)
                client.put(boat)
            return '', 204
        if request.method == 'DELETE':
            if load['carrier'] == boat['id']:
                load['carrier'] = None
                boat['loads'].remove(load['id'])
                client.put(load)
                client.put(boat)
                return '', 204
            else:
                error = {'Error': 'No load with this load_id exists on a '
                                  'boat with this boat_id'}
                return json.dumps(error), 404
    else:
        return 'Method not recognized', 405


def get_boat(boat_id, sub):
    """
    Helper function to get boat by boat_id
    """
    if request.headers['Accept'] != 'application/json':
        error = {'Error': 'The accepted MIME type is not supported'}
        return json.dumps(error), 406
    boat_key = client.key(constants.boats, int(boat_id))
    boat = client.get(key=boat_key)
    if boat is None or boat['owner'] != 'auth0|' + str(sub):
        # Boat doesn't exist, return error to user
        error = {'Error': 'No boat with this boat_id exists for the owner of '
                          'the supplied JWT'}
        return json.dumps(error), 403
    return json.dumps(boat), 200


def get_load(load_id):
    """
    Helper function to get boat by boat_id
    """
    if request.headers['Accept'] != 'application/json':
        error = {'Error': 'The accepted MIME type is not supported'}
        return json.dumps(error), 406
    load_key = client.key(constants.loads, int(load_id))
    load = client.get(key=load_key)
    if load is None:
        # Load doesn't exist, return error to user
        error = {'Error': 'No load with this load_id exists'}
        return json.dumps(error), 404
    return json.dumps(load), 200


def post(entity_type, content, sub=None):
    """
    Helper function for post methods, making a new entity of the type specified
    """
    if request.headers['Accept'] != 'application/json':
        error = {'Error': 'The accepted MIME type is not supported'}
        return json.dumps(error), 406
    try:
        if entity_type == 'boats':
            # Attempt to create new boat with attributes sent by user
            new_entity = datastore.entity.Entity(key=client.key(
                constants.boats))
            new_entity.update({'name': content['name'], 'type': content[
                'type'], 'length': content['length'],
                'owner': "auth0|" + str(sub), 'loads': []})
        else:
            # Attempt to create new load with attributes sent by user
            new_entity = datastore.entity.Entity(key=client.key(
                constants.loads))
            new_entity.update({'volume': content['volume'], 'item': content[
                'item'], 'creation_date': content['creation_date'],
                'carrier': None})
        client.put(new_entity)
        # Create id and self attributes and re-upload
        new_entity.update({'id': int(new_entity.id),
                           'self': constants.app_url + entity_type + '/' + str(
                               new_entity.id)})
        client.put(new_entity)
        return new_entity, 201
    except:
        # Could not make entity with sent data, send error message
        error = {'Error': 'The request object is missing at least one of the '
                          'required attributes'}
        return json.dumps(error), 400


def get_entity(entity_type, sub=None):
    """
    Helper function for GET methods, using pagination to return 5 entities
    at a time
    """
    if request.headers['Accept'] != 'application/json':
        error = {'Error': 'The accepted MIME type is not supported'}
        return json.dumps(error), 406
    if entity_type == 'boats':
        # Query for all boats
        query = client.query(kind=constants.boats)
    else:
        query = client.query(kind=constants.loads)
    # Paginate, return 5 results at a time
    q_limit = int(request.args.get('limit', '5'))
    q_offset = int(request.args.get('offset', '0'))
    l_iterator = query.fetch(limit=q_limit, offset=q_offset)
    pages = l_iterator.pages
    results = list(next(pages))
    if l_iterator.next_page_token:
        # Create link to next page and set starting point for returns
        next_offset = q_offset + q_limit
        next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + \
            str(next_offset)
    else:
        next_url = None
    new_results = []
    if entity_type == 'boats':
        for e in results:
            # Iterate through results to remove boats not owned by user
            if e['owner'] == 'auth0|' + str(sub):
                new_results.append(e)
    else:
        new_results = results
    output = {entity_type: new_results, 'count': len(new_results)}
    if next_url:
        output['next'] = next_url
    return json.dumps(output), 200

    
def delete(entity_type, entity_id, sub=None):
    """
    Helper function for DELETE methods
    """
    if entity_type == 'boats':
        # Fetch boat details
        boat_key = client.key(constants.boats, int(entity_id))
        entity = client.get(key=boat_key)
        if entity is None or entity['owner'] != 'auth0|' + str(sub):
            # Boat doesn't exist or is owned by someone else
            error = {'Error': 'No boat with this boat_id exists for the '
                              'owner of the supplied JWT'}
            return json.dumps(error), 403
    else:
        load_key = client.key(constants.loads, int(entity_id))
        entity = client.get(key=load_key)
        if entity is None:
            error = {'Error': 'No load with this load_id exists'}
            return json.dumps(error), 404
    if entity_type == 'boats':
        for i in entity['loads']:
            load_key = client.key(constants.loads, int(i))
            load = client.get(key=load_key)
            load['carrier'] = None
            client.put(load)
    else:
        if entity['carrier']:
            boat_key = client.key(constants.boats, int(entity['carrier']))
            boat = client.get(key=boat_key)
            boat['loads'].remove(entity['id'])
            client.put(boat)
    client.delete(entity)
    return '', 204


def put_patch(entity_type, method, content, entity_id, sub=None):
    """
    Helper function for PUT methods
    """
    if request.is_json is False:
        # Request object not a JSON
        error = {'Error': 'The request object must be a JSON file'}
        return json.dumps(error), 415
    if request.headers['Accept'] != 'application/json':
        # Unaccepted MIME type
        error = {'Error': 'The accepted MIME type is not supported'}
        return json.dumps(error), 406
    if 'id' in content or 'self' in content or 'owner' in content or 'loads'\
            in content or 'carrier' in content:
        # Request tried to update a parameter that may not be changed
        error = {'Error': 'The request contains attributes which may '
                          'not be edited'}
        return json.dumps(error), 400
    if entity_type == 'boats' and method == 'PUT':
        return put_boat(entity_id, content, sub)
    elif entity_type == 'boats' and method == 'PATCH':
        return patch_boat(entity_id, content, sub)
    elif entity_type == 'loads' and method == 'PUT':
        return put_load(entity_id, content)
    else:
        return patch_load(entity_id, content)
        
        
def put_boat(entity_id, content, sub):
    """
    Helper function for PUT method for boat entities
    """
    boat_key = client.key(constants.boats, int(entity_id))
    boat = client.get(key=boat_key)
    if boat is None or boat['owner'] != 'auth0|' + str(sub):
        # Boat doesn't exist, return error to user
        error = {'Error': 'No boat with this boat_id exists for the owner of '
                          'the supplied JWT'}
        return json.dumps(error), 403
    if 'name' not in content or 'type' not in content or 'length' \
            not in content:
        # Request object missing a required attribute
        error = {'Error': 'The request object is missing at least one of the '
                          'required attributes'}
        return json.dumps(error), 400
    try:
        # Attempt to create new boat with attributes sent by user
        boat.update({'name': content['name'], 'type': content[
            'type'], 'length': content['length']})
        client.put(boat)
        # Create 'self' and id attributes and re-upload
        boat.update({'id': int(boat.id), 'name': content[
            'name'], 'type': content['type'], 'length': content[
            'length'], 'self': constants.app_url + 'boats/'
                               + str(boat.id)})
        client.put(boat)
        return json.dumps(boat), 200
    except:
        # Could not make boat with sent data, send error message
        error = {'Error': 'The boat object could not be updated'}
        return json.dumps(error), 400


def put_load(entity_id, content):
    """
    Helper function for PUT method for load entities
    """
    load_key = client.key(constants.loads, int(entity_id))
    load = client.get(key=load_key)
    if load is None:
        # Load doesn't exist, return error to user
        error = {'Error': 'No load with this load_id exists'}
        return json.dumps(error), 404
    if 'volume' not in content or 'item' not in content or 'creation_date' \
            not in content:
        # Request object missing a required attribute
        error = {'Error': 'The request object is missing at least one of the '
                          'required attributes'}
        return json.dumps(error), 400
    try:
        # Attempt to create new boat with attributes sent by user
        load.update({'volume': content['volume'], 'item': content['item'],
                     'creation_date': content['creation_date']})
        client.put(load)
        # Create 'self' and id attributes and re-upload
        load.update({'id': int(load.id), 'volume': content['volume'],
                     'item': content['item'], 'creation_date': content[
                     'creation_date'], 'self': constants.app_url + 'loads/'
                     + str(load.id)})
        client.put(load)
        return json.dumps(load), 200
    except:
        # Could not make boat with sent data, send error message
        error = {'Error': 'The load object could not be updated'}
        return json.dumps(error), 400
        
        
def patch_boat(entity_id, content, sub):
    """
    Helper function for PUT method for boat entities
    """
    boat_key = client.key(constants.boats, int(entity_id))
    boat = client.get(key=boat_key)
    if boat is None or boat['owner'] != 'auth0|' + str(sub):
        # Boat doesn't exist, return error to user
        error = {'Error': 'No boat with this boat_id exists for the owner of '
                          'the supplied JWT'}
        return json.dumps(error), 403
    if 'name' in content and 'type' in content and 'length' in content:
        # Request object missing a required attribute
        error = {'Error': 'The request cannot edit all attributes'}
        return json.dumps(error), 400
    try:
        # Attempt to create new boat with attributes sent by user
        if 'name' in content:
            boat.update({'name': content['name']})
            client.put(boat)
        if 'type' in content:
            boat.update({'type': content['type']})
            client.put(boat)
        if 'length' in content:
            boat.update({'length': content['length']})
            client.put(boat)
        return json.dumps(boat), 200
    except:
        # Could not make boat with sent data, send error message
        error = {'Error': 'The boat object could not be updated'}
        return json.dumps(error), 400


def patch_load(entity_id, content):
    """
    Helper function for PUT method for load entities
    """
    load_key = client.key(constants.loads, int(entity_id))
    load = client.get(key=load_key)
    if load is None:
        # Load doesn't exist, return error to user
        error = {'Error': 'No load with this load_id exists'}
        return json.dumps(error), 404
    if 'volume' in content and 'item' in content and 'creation_date' in \
            content:
        # Request object missing a required attribute
        error = {'Error': 'The request cannot edit all attributes'}
        return json.dumps(error), 400
    try:
        # Attempt to create new boat with attributes sent by user
        if 'volume' in content:
            load.update({'volume': content['volume']})
            client.put(load)
        if 'item' in content:
            load.update({'item': content['item']})
            client.put(load)
        if 'creation_date' in content:
            load.update({'creation_date': content['creation_date']})
            client.put(load)
        return json.dumps(load), 200
    except:
        # Could not make boat with sent data, send error message
        error = {'Error': 'The load object could not be updated'}
        return json.dumps(error), 400


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
