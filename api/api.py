from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps

app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = 'your-secret-key'  # Change this to a secure random key

# In-memory storage
admins = []
users = []

# Create initial admin user
admin = {
    'id': 1,
    'name': 'Admin',
    'email': 'admin@example.com',
    'password': generate_password_hash('admin123', method='pbkdf2:sha256'),
    'created_at': datetime.datetime.utcnow().isoformat()
}
admins.append(admin)

# JWT token authentication decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in headers
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            if auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
        
        # Check for token in query params (for browser testing)
        if not token and 'token' in request.args:
            token = request.args.get('token')
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_admin = next((a for a in admins if a['id'] == data['admin_id']), None)
            if not current_admin:
                return jsonify({'message': 'Invalid token!'}), 401
        except:
            return jsonify({'message': 'Token is invalid!'}), 401
        
        return f(current_admin, *args, **kwargs)
    
    return decorated

# OpenAPI/Swagger documentation
SWAGGER_UI_HTML = '''
<!DOCTYPE html>
<html>
<head>
    <title>Admin API Documentation</title>
    <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@3/swagger-ui.css">
    <style>
        body {
            margin: 0;
            padding: 0;
            background-color: #fafafa;
        }
        #swagger-ui {
            padding: 20px;
        }
        .topbar {
            display: none;
        }
        .information-container {
            display: none;
        }
        .try-out {
            display: none;
        }
    </style>
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-bundle.js"></script>
    <script>
        const spec = {
            openapi: "3.0.0",
            info: {
                title: "Admin API",
                description: "API for managing users and admin authentication",
                version: "1.0.0",
                contact: {
                    email: "admin@example.com"
                }
            },
            servers: [
                {
                    url: window.location.origin,
                    description: "Current server"
                }
            ],
            tags: [
                {
                    name: "Authentication",
                    description: "Admin authentication endpoints"
                },
                {
                    name: "Users",
                    description: "User management endpoints"
                },
                {
                    name: "Utilities",
                    description: "Utility endpoints"
                }
            ],
            paths: {
                "/api/admin/login": {
                    post: {
                        tags: ["Authentication"],
                        summary: "Admin login",
                        description: "Authenticate as an admin and receive a JWT token",
                        requestBody: {
                            description: "Admin credentials",
                            required: true,
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object",
                                        properties: {
                                            email: {
                                                type: "string",
                                                example: "admin@example.com"
                                            },
                                            password: {
                                                type: "string",
                                                example: "admin123"
                                            }
                                        },
                                        required: ["email", "password"]
                                    }
                                }
                            }
                        },
                        responses: {
                            "200": {
                                description: "Successful login",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                token: {
                                                    type: "string",
                                                    description: "JWT token for authentication"
                                                },
                                                admin: {
                                                    type: "object",
                                                    properties: {
                                                        id: { type: "integer" },
                                                        name: { type: "string" },
                                                        email: { type: "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                description: "Missing email or password"
                            },
                            "401": {
                                description: "Invalid credentials"
                            }
                        }
                    }
                },
                "/api/admin/verify": {
                    get: {
                        tags: ["Authentication"],
                        summary: "Verify admin token",
                        description: "Verify if the provided JWT token is valid",
                        security: [{"BearerAuth": []}],
                        responses: {
                            "200": {
                                description: "Token is valid",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" },
                                                admin: {
                                                    type: "object",
                                                    properties: {
                                                        id: { type: "integer" },
                                                        name: { type: "string" },
                                                        email: { type: "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {
                                description: "Token is missing or invalid"
                            }
                        }
                    }
                },
                "/api/admin/users": {
                    get: {
                        tags: ["Users"],
                        summary: "List all users",
                        description: "Get a list of all registered users (admin only)",
                        security: [{"BearerAuth": []}],
                        responses: {
                            "200": {
                                description: "List of users",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "array",
                                            items: {
                                                type: "object",
                                                properties: {
                                                    id: { type: "integer" },
                                                    name: { type: "string" },
                                                    email: { type: "string" },
                                                    createdAt: { type: "string" }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "401": {
                                description: "Unauthorized"
                            }
                        }
                    },
                    post: {
                        tags: ["Users"],
                        summary: "Create a new user",
                        description: "Create a new user account (admin only)",
                        security: [{"BearerAuth": []}],
                        requestBody: {
                            description: "User details",
                            required: true,
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object",
                                        properties: {
                                            name: { type: "string", example: "John Doe" },
                                            email: { type: "string", example: "john@example.com" },
                                            password: { type: "string", example: "password123" }
                                        },
                                        required: ["name", "email", "password"]
                                    }
                                }
                            }
                        },
                        responses: {
                            "201": {
                                description: "User created successfully",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" },
                                                user: {
                                                    type: "object",
                                                    properties: {
                                                        id: { type: "integer" },
                                                        name: { type: "string" },
                                                        email: { type: "string" },
                                                        createdAt: { type: "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                description: "Missing required fields"
                            },
                            "409": {
                                description: "Email already registered"
                            },
                            "401": {
                                description: "Unauthorized"
                            }
                        }
                    }
                },
                "/api/admin/users/{user_id}": {
                    put: {
                        tags: ["Users"],
                        summary: "Update a user",
                        description: "Update an existing user account (admin only)",
                        security: [{"BearerAuth": []}],
                        parameters: [
                            {
                                name: "user_id",
                                in: "path",
                                description: "ID of the user to update",
                                required: true,
                                schema: {
                                    type: "integer"
                                }
                            }
                        ],
                        requestBody: {
                            description: "User details to update",
                            required: true,
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object",
                                        properties: {
                                            name: { type: "string", example: "Updated Name" },
                                            email: { type: "string", example: "updated@example.com" },
                                            password: { type: "string", example: "newpassword123" }
                                        }
                                    }
                                }
                            }
                        },
                        responses: {
                            "200": {
                                description: "User updated successfully",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" },
                                                user: {
                                                    type: "object",
                                                    properties: {
                                                        id: { type: "integer" },
                                                        name: { type: "string" },
                                                        email: { type: "string" },
                                                        createdAt: { type: "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                description: "No data provided"
                            },
                            "404": {
                                description: "User not found"
                            },
                            "409": {
                                description: "Email already in use"
                            },
                            "401": {
                                description: "Unauthorized"
                            }
                        }
                    },
                    delete: {
                        tags: ["Users"],
                        summary: "Delete a user",
                        description: "Delete an existing user account (admin only)",
                        security: [{"BearerAuth": []}],
                        parameters: [
                            {
                                name: "user_id",
                                in: "path",
                                description: "ID of the user to delete",
                                required: true,
                                schema: {
                                    type: "integer"
                                }
                            }
                        ],
                        responses: {
                            "200": {
                                description: "User deleted successfully",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" }
                                            }
                                        }
                                    }
                                }
                            },
                            "404": {
                                description: "User not found"
                            },
                            "401": {
                                description: "Unauthorized"
                            }
                        }
                    }
                },
                "/api/register": {
                    post: {
                        tags: ["Users"],
                        summary: "Register a new user",
                        description: "Register a new user account (simulates mobile app registration)",
                        requestBody: {
                            description: "User details",
                            required: true,
                            content: {
                                "application/json": {
                                    schema: {
                                        type: "object",
                                        properties: {
                                            name: { type: "string", example: "New User" },
                                            email: { type: "string", example: "new@example.com" },
                                            password: { type: "string", example: "password123" }
                                        },
                                        required: ["name", "email", "password"]
                                    }
                                }
                            }
                        },
                        responses: {
                            "201": {
                                description: "User registered successfully",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" },
                                                user: {
                                                    type: "object",
                                                    properties: {
                                                        id: { type: "integer" },
                                                        name: { type: "string" },
                                                        email: { type: "string" },
                                                        createdAt: { type: "string" }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            },
                            "400": {
                                description: "Missing required fields"
                            },
                            "409": {
                                description: "Email already registered"
                            }
                        }
                    }
                },
                "/api/sample-data": {
                    get: {
                        tags: ["Utilities"],
                        summary: "Add sample data",
                        description: "Add sample user data for testing",
                        responses: {
                            "200": {
                                description: "Sample data added or already exists",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                },
                "/setup": {
                    get: {
                        tags: ["Utilities"],
                        summary: "Setup information",
                        description: "View admin setup information",
                        responses: {
                            "200": {
                                description: "Setup information",
                                content: {
                                    "application/json": {
                                        schema: {
                                            type: "object",
                                            properties: {
                                                message: { type: "string" },
                                                admin_email: { type: "string" },
                                                admin_password: { type: "string" }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            components: {
                securitySchemes: {
                    BearerAuth: {
                        type: "http",
                        scheme: "bearer",
                        bearerFormat: "JWT"
                    }
                }
            }
        };

        // Initialize Swagger UI
        const ui = SwaggerUIBundle({
            spec: spec,
            dom_id: '#swagger-ui',
            presets: [
                SwaggerUIBundle.presets.apis,
                SwaggerUIStandalonePreset
            ],
            layout: "BaseLayout",
            deepLinking: true,
            showExtensions: true,
            showCommonExtensions: true
        });
    </script>
    <script src="https://unpkg.com/swagger-ui-dist@3/swagger-ui-standalone-preset.js"></script>
</body>
</html>
'''

# Routes
@app.route('/')
def home():
    return render_template_string(SWAGGER_UI_HTML)

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    data = request.get_json()
    
    if not data or not data.get('email') or not data.get('password'):
        return jsonify({'message': 'Missing email or password'}), 400
    
    admin = next((a for a in admins if a['email'] == data['email']), None)
    
    if not admin or not check_password_hash(admin['password'], data['password']):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    # Generate JWT token
    token = jwt.encode({
        'admin_id': admin['id'],
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    return jsonify({
        'token': token,
        'admin': {
            'id': admin['id'],
            'name': admin['name'],
            'email': admin['email']
        }
    })

@app.route('/api/admin/verify', methods=['GET'])
@token_required
def verify_token(current_admin):
    return jsonify({
        'message': 'Token is valid',
        'admin': {
            'id': current_admin['id'],
            'name': current_admin['name'],
            'email': current_admin['email']
        }
    })

@app.route('/api/admin/users', methods=['GET'])
@token_required
def get_users(current_admin):
    # Return users without password field
    user_list = []
    for user in users:
        user_data = {k: v for k, v in user.items() if k != 'password'}
        user_list.append(user_data)
    
    return jsonify(user_list)

@app.route('/api/admin/users', methods=['POST'])
@token_required
def create_user(current_admin):
    data = request.get_json()
    
    if not data or not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if email is already taken
    if any(u['email'] == data['email'] for u in users):
        return jsonify({'message': 'Email already registered'}), 409
    
    # Generate a unique ID (normally handled by the database)
    user_id = len(users) + 1
    
    # Create new user
    new_user = {
        'id': user_id,
        'name': data['name'],
        'email': data['email'],
        'password': generate_password_hash(data['password'], method='pbkdf2:sha256'),
        'createdAt': datetime.datetime.utcnow().isoformat()
    }
    
    users.append(new_user)
    
    # Return user without password
    user_response = {k: v for k, v in new_user.items() if k != 'password'}
    
    return jsonify({
        'message': 'User created successfully',
        'user': user_response
    }), 201

@app.route('/api/admin/users/<int:user_id>', methods=['PUT'])
@token_required
def update_user(current_admin, user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    data = request.get_json()
    
    if not data:
        return jsonify({'message': 'No data provided'}), 400
    
    # Update name if provided
    if 'name' in data:
        user['name'] = data['name']
    
    # Update email if provided
    if 'email' in data and data['email'] != user['email']:
        # Check if new email is already taken
        if any(u['email'] == data['email'] for u in users if u['id'] != user_id):
            return jsonify({'message': 'Email already in use'}), 409
        user['email'] = data['email']
    
    # Update password if provided
    if 'password' in data and data['password']:
        user['password'] = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Return user without password
    user_response = {k: v for k, v in user.items() if k != 'password'}
    
    return jsonify({
        'message': 'User updated successfully',
        'user': user_response
    })

@app.route('/api/admin/users/<int:user_id>', methods=['DELETE'])
@token_required
def delete_user(current_admin, user_id):
    user = next((u for u in users if u['id'] == user_id), None)
    
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    users.remove(user)
    
    return jsonify({'message': 'User deleted successfully'})

# Endpoint to simulate user registration from the mobile app
@app.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json()
    
    if not data or not all(k in data for k in ('name', 'email', 'password')):
        return jsonify({'message': 'Missing required fields'}), 400
    
    # Check if email is already taken
    if any(u['email'] == data['email'] for u in users):
        return jsonify({'message': 'Email already registered'}), 409
    
    # Generate a unique ID
    user_id = len(users) + 1
    
    # Create new user
    new_user = {
        'id': user_id,
        'name': data['name'],
        'email': data['email'],
        'password': generate_password_hash(data['password'], method='pbkdf2:sha256'),
        'createdAt': datetime.datetime.utcnow().isoformat()
    }
    
    users.append(new_user)
    
    # Return user without password
    user_response = {k: v for k, v in new_user.items() if k != 'password'}
    
    return jsonify({
        'message': 'User registered successfully',
        'user': user_response
    }), 201

# Setup endpoint is now just for information
@app.route('/setup', methods=['GET'])
def setup():
    return jsonify({
        'message': 'Admin user is already set up',
        'admin_email': 'admin@example.com',
        'admin_password': 'admin123'
    })

# Add some sample users for testing
@app.route('/api/sample-data', methods=['GET'])
def add_sample_data():
    if not users:  # Only add if no users exist
        sample_users = [
            {
                'id': 1,
                'name': 'John Doe',
                'email': 'john@example.com',
                'password': generate_password_hash('password123', method='pbkdf2:sha256'),
                'createdAt': (datetime.datetime.utcnow() - datetime.timedelta(days=10)).isoformat()
            },
            {
                'id': 2,
                'name': 'Jane Smith',
                'email': 'jane@example.com',
                'password': generate_password_hash('password123', method='pbkdf2:sha256'),
                'createdAt': (datetime.datetime.utcnow() - datetime.timedelta(days=5)).isoformat()
            },
            {
                'id': 3,
                'name': 'Bob Johnson',
                'email': 'bob@example.com',
                'password': generate_password_hash('password123', method='pbkdf2:sha256'),
                'createdAt': datetime.datetime.utcnow().isoformat()
            }
        ]
        users.extend(sample_users)
        return jsonify({'message': 'Sample data added successfully'})
    return jsonify({'message': 'Sample data already exists'})

if __name__ == '__main__':
    app.run(debug=True)