from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename
import boto3
from botocore.exceptions import ClientError
import uuid
import os
from datetime import datetime
from decimal import Decimal
import traceback
import json

def convert_floats_to_decimal(obj):
    """
    Recursively convert all float values in dict/list to Decimal
    so they can be safely stored in DynamoDB.
    """
    if isinstance(obj, list):
        return [convert_floats_to_decimal(i) for i in obj]
    elif isinstance(obj, dict):
        return {k: convert_floats_to_decimal(v) for k, v in obj.items()}
    elif isinstance(obj, float):
        return Decimal(str(obj))  # Convert float to Decimal
    else:
        return obj

app = Flask(__name__)
app.config['SECRET_KEY'] = 'p1r2o3d4u5c6t7r8e9v10i11e12w13a14n15a16l17y18z19e20r21'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# AWS Configuration
AWS_REGION = 'us-east-1'
BUCKET_NAME = "product-review-storage-bucket"
PRODUCTS_TABLE = "product-reviews"
USERS_TABLE = "review-users"
ANALYTICS_TABLE = "product-analytics"

# AWS clients
s3 = boto3.client('s3', region_name=AWS_REGION)
rekognition = boto3.client('rekognition', region_name=AWS_REGION)
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION)
products_table = dynamodb.Table(PRODUCTS_TABLE)
users_table = dynamodb.Table(USERS_TABLE)
analytics_table = dynamodb.Table(ANALYTICS_TABLE)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def login_required(f):
    """Decorator to protect routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Please login first', 'error')
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to protect admin routes"""
    from functools import wraps
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session or session.get('role') != 'admin':
            flash('Admin access required', 'error')
            return redirect(url_for('home'))
        return f(*args, **kwargs)
    return decorated_function

def analyze_product_image(image_bytes):
    """Use Rekognition to detect labels and analyze product quality"""
    try:
        print(f"[REKOGNITION] Analyzing image...")
        
        # Detect labels
        labels_response = rekognition.detect_labels(
            Image={'Bytes': image_bytes},
            MaxLabels=20,
            MinConfidence=70
        )
        
        # Detect moderation labels (for detecting defects/damage)
        moderation_response = rekognition.detect_moderation_labels(
            Image={'Bytes': image_bytes},
            MinConfidence=60
        )
        
        # Detect text in image (for brand names, expiry dates, etc.)
        text_response = rekognition.detect_text(
            Image={'Bytes': image_bytes}
        )
        
        labels = []
        for label in labels_response['Labels']:
            labels.append({
                'name': label['Name'],
                'confidence': float(label['Confidence']),
                'parents': [p['Name'] for p in label.get('Parents', [])]
            })
        
        moderation_labels = []
        for label in moderation_response['ModerationLabels']:
            moderation_labels.append({
                'name': label['Name'],
                'confidence': float(label['Confidence']),
                'parent': label.get('ParentName', '')
            })
        
        detected_text = []
        for text in text_response['TextDetections']:
            if text['Type'] == 'LINE':
                detected_text.append({
                    'text': text['DetectedText'],
                    'confidence': float(text['Confidence'])
                })
        
        # Determine product type from labels
        product_type = determine_product_type(labels)
        
        # Detect potential defects
        has_defects = len(moderation_labels) > 0 or detect_quality_issues(labels)
        
        print(f"[REKOGNITION] Analysis complete. Product type: {product_type}, Defects detected: {has_defects}")
        
        return {
            'labels': labels,
            'moderation_labels': moderation_labels,
            'detected_text': detected_text,
            'product_type': product_type,
            'has_defects': has_defects,
            'quality_score': calculate_quality_score(labels, moderation_labels)
        }
        
    except Exception as e:
        print(f"[REKOGNITION] Error: {str(e)}")
        raise

def determine_product_type(labels):
    """Determine product category from detected labels"""
    product_categories = {
        'Electronics': ['Electronics', 'Phone', 'Computer', 'Laptop', 'Camera', 'Television', 'Monitor'],
        'Clothing': ['Clothing', 'Apparel', 'Shirt', 'Pants', 'Dress', 'Shoe', 'Fashion'],
        'Food': ['Food', 'Fruit', 'Vegetable', 'Meal', 'Snack', 'Beverage', 'Drink'],
        'Furniture': ['Furniture', 'Chair', 'Table', 'Sofa', 'Desk', 'Bed'],
        'Beauty': ['Cosmetics', 'Perfume', 'Makeup', 'Beauty Product'],
        'Toys': ['Toy', 'Game', 'Doll', 'Action Figure'],
        'Books': ['Book', 'Magazine', 'Publication', 'Text'],
        'Sports': ['Sports Equipment', 'Ball', 'Fitness', 'Exercise'],
        'Automotive': ['Vehicle', 'Car', 'Automobile', 'Transportation']
    }
    
    for label in labels:
        for category, keywords in product_categories.items():
            if any(keyword.lower() in label['name'].lower() for keyword in keywords):
                return category
    
    return 'General Product'

def detect_quality_issues(labels):
    """Detect potential quality issues from labels"""
    defect_keywords = ['damaged', 'broken', 'crack', 'scratch', 'torn', 'worn', 'dirty', 'stain']
    
    for label in labels:
        if any(keyword in label['name'].lower() for keyword in defect_keywords):
            return True
    
    return False

def calculate_quality_score(labels, moderation_labels):
    """Calculate quality score (0-100) based on analysis"""
    base_score = 100
    
    # Deduct points for moderation labels (potential defects)
    base_score -= len(moderation_labels) * 15
    
    # Deduct points for quality issues detected in labels
    quality_keywords = ['damaged', 'broken', 'crack', 'scratch']
    for label in labels:
        if any(keyword in label['name'].lower() for keyword in quality_keywords):
            base_score -= 10
    
    return max(0, min(100, base_score))

def init_aws_resources():
    """Initialize all AWS resources"""
    print("\n" + "="*60)
    print("Initializing AWS Resources for Product Review Analyzer...")
    print("="*60)
    
    try:
        # 1. Create S3 bucket
        try:
            s3.head_bucket(Bucket=BUCKET_NAME)
            print(f"✓ S3 bucket '{BUCKET_NAME}' exists")
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code == '404':
                try:
                    if AWS_REGION == 'us-east-1':
                        s3.create_bucket(Bucket=BUCKET_NAME)
                    else:
                        s3.create_bucket(
                            Bucket=BUCKET_NAME,
                            CreateBucketConfiguration={'LocationConstraint': AWS_REGION}
                        )
                    print(f"✓ Created S3 bucket '{BUCKET_NAME}'")
                except ClientError as create_error:
                    print(f"✗ Failed to create S3 bucket: {str(create_error)}")
            else:
                print(f"✗ S3 bucket check failed: {str(e)}")
        
        # 2. Check DynamoDB tables
        tables_config = {
            PRODUCTS_TABLE: "Partition key: review_id (String), GSI: product_type-created_at-index",
            USERS_TABLE: "Partition key: user_id (String)",
            ANALYTICS_TABLE: "Partition key: product_type (String), Sort key: date (String)"
        }
        
        for table_name, config in tables_config.items():
            try:
                table = dynamodb.Table(table_name)
                table.load()
                print(f"✓ DynamoDB table '{table_name}' exists")
            except ClientError as e:
                if e.response['Error']['Code'] == 'ResourceNotFoundException':
                    print(f"✗ DynamoDB table '{table_name}' does NOT exist")
                    print(f"   Please create it manually with: {config}")
                else:
                    print(f"✗ Error checking table: {str(e)}")
        
        print("="*60)
        print("AWS Resource Initialization Complete")
        print("="*60 + "\n")
            
    except Exception as e:
        print(f"\n✗ AWS initialization error: {str(e)}")
        print(traceback.format_exc())
        print("="*60 + "\n")



# ==================== HTML PAGE ROUTES ====================

@app.route('/')
def home():
    """Home page - Landing page"""
    return render_template('index.html')

@app.route('/login')
def login_page():
    """Login page"""
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('customer_dashboard'))
    return render_template('login.html')

@app.route('/register')
def register_page():
    """Register page"""
    if 'user_id' in session:
        return redirect(url_for('customer_dashboard'))
    return render_template('register.html')

@app.route('/customer/dashboard')
@login_required
def customer_dashboard():
    """Customer dashboard - Upload and view reviews"""
    try:
        user_id = session['user_id']
        
        # Get user's reviews
        response = products_table.scan(
            FilterExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        
        reviews = response.get('Items', [])
        
        # Sort by created_at descending
        reviews.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return render_template('customer_dashboard.html', 
                             username=session.get('username'),
                             reviews=reviews[:20])
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/admin/dashboard')
@admin_required
def admin_dashboard():
    """Admin dashboard - View all reviews and analytics"""
    try:
        # Get all reviews
        response = products_table.scan(Limit=50)
        reviews = response.get('Items', [])
        
        # Calculate statistics
        total_reviews = len(reviews)
        product_types = {}
        avg_quality = 0
        defect_count = 0
        
        for review in reviews:
            # Count by product type
            ptype = review.get('product_type', 'Unknown')
            product_types[ptype] = product_types.get(ptype, 0) + 1
            
            # Quality scores
            if 'quality_score' in review:
                avg_quality += review['quality_score']
            
            # Defect count
            if review.get('has_defects', False):
                defect_count += 1
        
        avg_quality = avg_quality / total_reviews if total_reviews > 0 else 0
        
        # Sort reviews by date
        reviews.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        analytics = {
            'total_reviews': total_reviews,
            'product_types': product_types,
            'avg_quality_score': round(avg_quality, 2),
            'defect_rate': round((defect_count / total_reviews * 100) if total_reviews > 0 else 0, 2),
            'recent_reviews': reviews[:10]
        }
        
        return render_template('admin_dashboard.html', 
                             username=session.get('username'),
                             analytics=analytics)
        
    except Exception as e:
        flash(f'Error loading dashboard: {str(e)}', 'error')
        return redirect(url_for('home'))

@app.route('/review/<review_id>')
@login_required
def review_detail(review_id):
    """View detailed review"""
    try:
        response = products_table.get_item(Key={'review_id': review_id})
        
        if 'Item' not in response:
            flash('Review not found', 'error')
            return redirect(url_for('customer_dashboard'))
        
        review = response['Item']
        
        # Check if user has access (admin or owner)
        if session.get('role') != 'admin' and review.get('user_id') != session.get('user_id'):
            flash('Access denied', 'error')
            return redirect(url_for('customer_dashboard'))
        
        return render_template('review_detail.html', review=review)
        
    except Exception as e:
        flash(f'Error loading review: {str(e)}', 'error')
        return redirect(url_for('customer_dashboard'))

# ==================== API ROUTES ====================

@app.route('/api/register', methods=['POST'])
def api_register():
    """API: Register new user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data or 'email' not in data:
            return jsonify({'error': 'Username, email, and password required'}), 400
        
        username = data['username'].strip()
        email = data['email'].strip().lower()
        password = data['password']
        role = data.get('role', 'customer')  # Default to customer
        
        # Check if user exists
        response = users_table.scan(
            FilterExpression='username = :uname OR email = :email',
            ExpressionAttributeValues={':uname': username, ':email': email}
        )
        
        if response.get('Items'):
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Create user
        user_id = str(uuid.uuid4())
        
        users_table.put_item(
            Item={
                'user_id': user_id,
                'username': username,
                'email': email,
                'password': password,  # In production, hash this!
                'role': role,
                'created_at': datetime.now().isoformat(),
                'total_reviews': 0
            }
        )
        
        return jsonify({
            'success': True,
            'message': 'Registration successful',
            'redirect': url_for('login_page')
        }), 201
        
    except Exception as e:
        print(f"[REGISTER] Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Registration failed: {str(e)}'}), 500

@app.route('/api/login', methods=['POST'])
def api_login():
    """API: Login user"""
    try:
        data = request.get_json()
        
        if not data or 'username' not in data or 'password' not in data:
            return jsonify({'error': 'Username and password required'}), 400
        
        username = data['username'].strip()
        password = data['password']
        
        # Find user
        response = users_table.scan(
            FilterExpression='username = :uname',
            ExpressionAttributeValues={':uname': username}
        )
        
        users = response.get('Items', [])
        
        if not users or users[0]['password'] != password:
            return jsonify({'error': 'Invalid credentials'}), 401
        
        user = users[0]
        
        # Set session
        session['user_id'] = user['user_id']
        session['username'] = user['username']
        session['role'] = user.get('role', 'customer')
        
        redirect_url = url_for('admin_dashboard') if user.get('role') == 'admin' else url_for('customer_dashboard')
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'role': user.get('role', 'customer'),
            'redirect': redirect_url
        }), 200
        
    except Exception as e:
        print(f"[LOGIN] Error: {str(e)}")
        return jsonify({'error': f'Login failed: {str(e)}'}), 500

@app.route('/api/upload-review', methods=['POST'])
@login_required
def api_upload_review():
    """API: Upload product image and create review"""
    try:
        print("\n[UPLOAD] Starting product review upload...")
        
        if 'image' not in request.files:
            return jsonify({'error': 'No image provided'}), 400
        
        file = request.files['image']
        product_name = request.form.get('product_name', 'Unnamed Product')
        rating = int(request.form.get('rating', 5))
        comment = request.form.get('comment', '')
        
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if not allowed_file(file.filename):
            return jsonify({'error': 'Invalid file type. Use PNG, JPG, or JPEG'}), 400
        
        # Read image
        image_bytes = file.read()
        print(f"[UPLOAD] Image size: {len(image_bytes)} bytes")
        
        # Analyze image with Rekognition
        analysis = analyze_product_image(image_bytes)
        
        # Generate unique IDs
        review_id = str(uuid.uuid4())
        filename = f"reviews/{session['user_id']}/{review_id}/{secure_filename(file.filename)}"
        
        print(f"[UPLOAD] Uploading to S3: {filename}")
        # Upload to S3
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=filename,
            Body=image_bytes,
            ContentType=file.content_type
        )
        
        # Store review in DynamoDB
        review_item = {
            'review_id': review_id,
            'user_id': session['user_id'],
            'username': session['username'],
            'product_name': product_name,
            'rating': rating,
            'comment': comment,
            's3_key': filename,
            'product_type': analysis['product_type'],
            'quality_score': analysis['quality_score'],
            'has_defects': analysis['has_defects'],
            'labels': analysis['labels'][:10],  # Store top 10 labels
            'detected_text': analysis['detected_text'][:5],
            'moderation_labels': analysis['moderation_labels'],
            'created_at': datetime.now().isoformat()
        }
        review_item = convert_floats_to_decimal(review_item)

# Now safe to store in DynamoDB
        products_table.put_item(Item=review_item)

        
        # Update user's review count
        users_table.update_item(
            Key={'user_id': session['user_id']},
            UpdateExpression='SET total_reviews = total_reviews + :inc',
            ExpressionAttributeValues={':inc': 1}
        )
        
        # Update analytics
        update_analytics(analysis['product_type'], analysis['quality_score'], analysis['has_defects'])
        
        print(f"[UPLOAD] Review uploaded successfully: {review_id}")
        
        return jsonify({
            'success': True,
            'message': 'Review uploaded successfully',
            'review_id': review_id,
            'product_type': analysis['product_type'],
            'quality_score': analysis['quality_score'],
            'has_defects': analysis['has_defects'],
            'redirect': url_for('review_detail', review_id=review_id)
        }), 201
        
    except Exception as e:
        print(f"[UPLOAD] Error: {str(e)}")
        print(traceback.format_exc())
        return jsonify({'error': f'Upload failed: {str(e)}'}), 500

def update_analytics(product_type, quality_score, has_defects):
    """Update analytics table with new review data"""
    try:
        today = datetime.now().strftime('%Y-%m-%d')
        
        # Get or create analytics entry
        response = analytics_table.get_item(
            Key={
                'product_type': product_type,
                'date': today
            }
        )
        
        if 'Item' in response:
            # Update existing
            analytics_table.update_item(
                Key={'product_type': product_type, 'date': today},
                UpdateExpression='SET review_count = review_count + :inc, total_quality_score = total_quality_score + :qs, defect_count = defect_count + :dc',
                ExpressionAttributeValues={
                    ':inc': 1,
                    ':qs': quality_score,
                    ':dc': 1 if has_defects else 0
                }
            )
        else:
            # Create new
            analytics_table.put_item(
                Item={
                    'product_type': product_type,
                    'date': today,
                    'review_count': 1,
                    'total_quality_score': quality_score,
                    'defect_count': 1 if has_defects else 0
                }
            )
            
    except Exception as e:
        print(f"[ANALYTICS] Error updating: {str(e)}")

@app.route('/api/reviews')
@login_required
def api_get_reviews():
    """API: Get reviews (filtered by user or all for admin)"""
    try:
        if session.get('role') == 'admin':
            # Admin sees all reviews
            response = products_table.scan(Limit=100)
        else:
            # Customer sees only their reviews
            response = products_table.scan(
                FilterExpression='user_id = :uid',
                ExpressionAttributeValues={':uid': session['user_id']}
            )
        
        reviews = response.get('Items', [])
        reviews.sort(key=lambda x: x.get('created_at', ''), reverse=True)
        
        return jsonify({
            'success': True,
            'reviews': reviews
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/analytics/summary')
@admin_required
def api_analytics_summary():
    """API: Get analytics summary for admin"""
    try:
        # Get recent analytics
        response = analytics_table.scan()
        analytics = response.get('Items', [])
        
        # Calculate summaries
        summary = {
            'by_product_type': {},
            'by_date': {}
        }
        
        for item in analytics:
            ptype = item['product_type']
            date = item['date']
            
            if ptype not in summary['by_product_type']:
                summary['by_product_type'][ptype] = {
                    'total_reviews': 0,
                    'avg_quality': 0,
                    'defect_rate': 0
                }
            
            summary['by_product_type'][ptype]['total_reviews'] += item.get('review_count', 0)
            summary['by_product_type'][ptype]['avg_quality'] += item.get('total_quality_score', 0)
            summary['by_product_type'][ptype]['defect_rate'] += item.get('defect_count', 0)
        
        # Calculate averages
        for ptype in summary['by_product_type']:
            data = summary['by_product_type'][ptype]
            if data['total_reviews'] > 0:
                data['avg_quality'] = round(data['avg_quality'] / data['total_reviews'], 2)
                data['defect_rate'] = round((data['defect_rate'] / data['total_reviews']) * 100, 2)
        
        return jsonify({
            'success': True,
            'summary': summary
        }), 200
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/logout', methods=['POST', 'GET'])
def api_logout():
    """API: Logout current user"""
    session.clear()
    
    if request.method == 'GET':
        flash('You have been logged out', 'success')
        return redirect(url_for('home'))
    
    return jsonify({'success': True, 'message': 'Logged out successfully'}), 200

# ==================== ERROR HANDLERS ====================

@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Endpoint not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def server_error(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

if __name__ == '__main__':
    # Initialize AWS resources on startup
    init_aws_resources()
    
    print("\nStarting Product Review Analyzer application...")
    print(f"Server will be available at: http://0.0.0.0:5000")
    print("Press CTRL+C to quit\n")
    

    app.run(host='0.0.0.0', port=5000, debug=True)


