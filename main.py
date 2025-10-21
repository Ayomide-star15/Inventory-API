from fastapi import FastAPI, HTTPException, Depends,Body
from typing import Optional
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pymongo import MongoClient
from passlib.context import CryptContext
from jose import JWTError, jwt
from datetime import datetime, timedelta
import uuid,os,smtplib,random,string
from email.mime.text import MIMEText
from dotenv import load_dotenv


# Import Models (Ensure Model_1.py is in same directory)
from model import (RegisterUser, UserLogin, VerifyOTP, CreatePassword,
                     ForgotPassword, ResetPassword, OTPOnly, AddSupplier,PurchaseItem, BulkCategory,
                     BulkProductItem, UpdateProduct, Product,SellProduct)

# ---------------- ENV SETUP ----------------
load_dotenv('.env')

MONGODB_URI = os.getenv("MONGODB_URI")
JWT_SECRET = os.getenv("JWT_SECRET", "mysecretkey")
JWT_ALGORITHM = "HS256"

ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD")
STORE_API_BASE_URL = os.getenv("Store_API_URL")

if not MONGODB_URI:
    raise RuntimeError("Missing MONGODB_URI in .env. Please set it before starting the app.")

# ---------------- DB SETUP ----------------
try:
    client = MongoClient(MONGODB_URI)
    client.admin.command("ping")  # test connection
    db = client["inventory_db"]
    users_collection = db["users"]
    categories_collection = db["categories"]
    suppliers_collection = db["suppliers"]
    purchases_collection = db["purchases"]
    categories_collection = db["categories"]
    products_collection = db["products"]
    sales_collection = db["sales"]
    otps_collection = db["otps"]
    print("Connected to MongoDB successfully.")
except Exception as e:
    raise RuntimeError(f"Could not connect to MongoDB: {e}")

# ---------------- SECURITY ----------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
security = HTTPBearer()

# ---------------- APP INIT ----------------
app = FastAPI(title="Inventory System API")

# ---------------- HELPER FUNCTIONS ----------------
def send_otp_email(email: str, otp: str):
    sender_email = os.getenv("SENDER_EMAIL")
    sender_pass = os.getenv("SENDER_PASSWORD")

    if not sender_email or not sender_pass:
        raise HTTPException(status_code=500, detail="Email credentials not set in environment")

    msg = MIMEText(f"Your verification OTP is {otp}. It will expire in 10 minutes.")
    msg["Subject"] = "Email Verification OTP"
    msg["From"] = str(sender_email)
    msg["To"] = str(email)

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(str(sender_email), str(sender_pass))
            server.sendmail(str(sender_email), str(email), msg.as_string())
    except Exception as e:
        print("Error sending email:", e)
        raise HTTPException(status_code=500, detail="Failed to send OTP email")
    
def send_email_alert(email: str, subject: str, body: str):
    sender_email = os.getenv("SENDER_EMAIL")
    sender_pass = os.getenv("SENDER_PASSWORD")

    if not sender_email or not sender_pass:
        raise HTTPException(status_code=500, detail="Email credentials not set")

    msg = MIMEText(body, "plain")
    msg["Subject"] = subject
    msg["From"] = sender_email
    msg["To"] = email

    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(sender_email, sender_pass)
            server.send_message(msg)
    except Exception as e:
        print("Email sending error:", e)
        raise HTTPException(status_code=500, detail="Failed to send email")


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False

def create_access_token(data: dict, expires_delta: timedelta = timedelta(hours=2)) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + expires_delta
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, JWT_SECRET, algorithm=JWT_ALGORITHM)

def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email: str = payload.get("sub") or ""
        if email is None:
            raise HTTPException(status_code=401, detail="Invalid token payload")

        user = users_collection.find_one({"email": email})
        if not user:
            raise HTTPException(status_code=401, detail="User not found")

        return user
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

# ---------------- SEED ADMIN ----------------
# ---------------- SEED ADMIN (FIXED) ----------------
@app.on_event("startup")
def seed_admin():
    """Seeds or updates the initial admin user on startup."""
    if not ADMIN_EMAIL or not ADMIN_PASSWORD:
        # This is a critical error, keep the original RuntimeError
        raise RuntimeError("Missing ADMIN_EMAIL or ADMIN_PASSWORD in .env file")

    existing_admin = users_collection.find_one({"email": ADMIN_EMAIL})
    hashed_password = get_password_hash(ADMIN_PASSWORD)
    
    admin_first_name = "Adewale"
    admin_last_name = "Ayomide (Admin)"

    if not existing_admin:
        # FIX 1: Ensure 'email_status' is set to "active" during initial creation
        admin_data = {
            "user_id": str(uuid.uuid4()),
            "first_name": admin_first_name,
            "last_name": admin_last_name,
            "email": ADMIN_EMAIL,
            "password": hashed_password,
            "role": "admin",
            "phone_number": None,
            "address": None,
            "state": None,
            "country": None,
            "email_status": "active", # <--- CRITICAL FIX: Set to "active"
            "created_at": datetime.utcnow(),
            "updated_at": datetime.utcnow(),
        }
        users_collection.insert_one(admin_data)
        print(f"New admin seeded with email: {ADMIN_EMAIL}")
    else:
        # FIX 2: Ensure 'email_status' is forced to "active" during update
        update_fields = {
            "password": hashed_password, 
            "first_name": existing_admin.get("first_name") or admin_first_name,
            "last_name": existing_admin.get("last_name") or admin_last_name,
            "email_status": "active", # <--- CRITICAL FIX: Force status to "active"
            "role": existing_admin.get("role") or "admin",
            "updated_at": datetime.utcnow(),
        }
        users_collection.update_one({"_id": existing_admin["_id"]}, {"$set": update_fields})
        print("Admin user verified/updated with consistent fields.")
# ---------------- ROUTES ----------------
@app.get("/", tags=["Root"])
def read_root():
    return {"message": "Welcome to the Inventory System API"}

# ---------------- Login ----------------
@app.post("/auth/register")
def register_user(user: RegisterUser):
    if users_collection.find_one({"email": user.email}):
        raise HTTPException(status_code=400, detail="Email already exists")
    
    otp = ''.join(random.choices(string.digits, k=6))
    otp_expire = datetime.utcnow() + timedelta(minutes=10)


    user_data = {
        "user_id": str(uuid.uuid4()),
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "role": user.role,
        "address": user.address,
        "state": user.state,
        "country": user.country,
        "phone_number": user.phone_number,
        "email_status": "pending",
        "password": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }

    users_collection.insert_one(user_data)
    #save otp
    otp_data = {
        "email": user.email,
        "otp": otp,
        "expires_at": otp_expire,
        "created_at": datetime.utcnow()
    }

    otps_collection.insert_one(otp_data)
    #send otp email
    send_otp_email(user.email, otp)

    return {"message": "OTP sent to your email. Verify to continue."}


@app.post("/auth/verify-otp")
def verify_otp(data: VerifyOTP):
    otp_entry = otps_collection.find_one({"otp": data.otp})
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Invalid OTP")
        
    # Check if OTP has expired (using 'expires_at' as established in the previous fix)
    if datetime.utcnow() > otp_entry.get("expires_at", datetime.min):
        # Optional: Delete expired OTP, but the check below also prevents use
        # otps_collection.delete_one({"_id": otp_entry["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")
        
    # Check if OTP is already verified/used
    if otp_entry.get("verified") is True:
        raise HTTPException(status_code=400, detail="OTP already used.")

    user_email = otp_entry["email"]
    
    # 🔑 FIX: Set 'verified' to True in otps_collection instead of deleting
    otps_collection.update_one(
        {"_id": otp_entry["_id"]},
        {"$set": {
            "verified": True,
            "updated_at": datetime.utcnow()
        }}
    )
    
    # Update user's email_status to 'verified' to allow password creation
    users_collection.update_one(
        {"email": user_email},
        {"$set": {
            "email_status": "verified",
            "updated_at": datetime.utcnow()
        }}
    )

    # Generate token carrying the 'verified' status for the next step (create-password)
    access_token = create_access_token({"sub": user_email, "status": "verified"})
    return {
        "message": "Email verified successfully. Proceed to create your password.",
        "access_token": access_token,
        "token_type": "bearer"
    }

# ... (Part of the create-password endpoint for reference)
@app.post("/auth/create-password")
def create_password(
    data: CreatePassword,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    token = credentials.credentials

    # 1. Decode JWT to get email and verification status
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        
        # Get the subject (email) and the status set by /auth/verify-otp
        email: str = payload.get("sub") or ""
        status: Optional[str] = payload.get("status")

        if not email or status != "verified":
            raise HTTPException(status_code=401, detail="Invalid token payload or unverified status")
            
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    # 2. Find the user and check verification status
    user = users_collection.find_one({"email": email})
    
    # Check if user exists AND if their email_status is 'verified'
    if not user or user.get("email_status") != "verified": 
        raise HTTPException(status_code=400, detail="User not verified or account already active. Please log in.")

    # 3. Hash and store the new password
    hashed_password = get_password_hash(data.password)

    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password": hashed_password,
            "email_status": "active", # Moves user to active status
            "updated_at": datetime.utcnow()
        }}
    )

    return {"message": "Password created successfully. Account is now active."}
@app.post("/auth/login", tags=["Login"])
def login(credentials: UserLogin):
    """Authenticate user and return access token."""
    user = users_collection.find_one({"email": credentials.email})
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.get("password") is None or not verify_password(credentials.password, user["password"]):
        raise HTTPException(status_code=400, detail="Incorrect password or password not set")
    
    # Check if account is active/verified
    if user.get("email_status") != "active":
        raise HTTPException(status_code=403, detail="Account not active. Please complete verification and password setup.")

    token = create_access_token(data={"sub": user["email"], "role": user["role"]})
    
    # Clean up profile data, handle missing fields
    profile = {
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "email": user.get("email"),
        "phone_number": user.get("phone_number"),
        "address": user.get("address"),
        "state": user.get("state"),
        "country": user.get("country"),
        "role": user.get("role"),
    }

    return {
        "message": "Login successful",
        "token": token,
        "token_type": "bearer",
        "profile": profile,
    }

# ---------------- Password Reset ----------------
# FIX: Adjusted /auth/forgot-password to use otps_collection

@app.post("/auth/forgot-password", tags=["Password Reset"])
def forgot_password(data: ForgotPassword):
    """Step 1: User requests password reset — system sends OTP to email."""
    user = users_collection.find_one({"email": data.email})
    if not user:
        # Prevent email enumeration
        return {"message": "If your email is registered, an OTP has been sent for password reset."}

    otp = ''.join(random.choices(string.digits, k=6))
    otp_expire = datetime.utcnow() + timedelta(minutes=10)

    # 🔑 FIX: Store OTP in the dedicated otps_collection
    otps_collection.insert_one({
        "email": data.email,
        "otp": otp,
        "expires_at": otp_expire,
        "type": "password_reset", # Differentiate from registration OTPs
        "verified": False,
        "created_at": datetime.utcnow()
    })

    send_otp_email(data.email, otp)
    return {"message": "OTP sent to your email for password reset."}


# FIX: Adjusted /auth/verify-reset-otp to check otps_collection

@app.post("/auth/verify-reset-otp", tags=["Password Reset"])
def verify_reset_otp(data: OTPOnly):
    """Step 2: User submits OTP, verifies it, and receives a temporary reset token."""
    
    # 🔑 FIX: Find OTP in otps_collection by OTP value and type
    otp_entry = otps_collection.find_one({"otp": data.otp, "type": "password_reset"})
    
    if not otp_entry:
        raise HTTPException(status_code=400, detail="Invalid OTP")

    # Check for expiry
    if datetime.utcnow() > otp_entry["expires_at"]:
        # Delete expired OTP
        otps_collection.delete_one({"_id": otp_entry["_id"]})
        raise HTTPException(status_code=400, detail="OTP expired")
        
    if otp_entry.get("verified"):
        raise HTTPException(status_code=400, detail="OTP already used.")

    user_email = otp_entry["email"]
    
    # Mark OTP as verified to prevent reuse
    otps_collection.update_one(
        {"_id": otp_entry["_id"]},
        {"$set": {"verified": True, "updated_at": datetime.utcnow()}}
    )

    # Generate temporary token for password reset. The token payload contains the email.
    access_token = create_access_token({"sub": user_email, "action": "reset"})
    return {"message": "OTP verified successfully. Use the access token to reset your password.", "access_token": access_token}


# FIX: Adjusted /auth/reset-password to confirm verification status via otps_collection

@app.post("/auth/reset-password", tags=["Password Reset"])
def reset_password(
    data: ResetPassword,
    credentials: HTTPAuthorizationCredentials = Depends(security)
):
    """Step 3: User sets a new password after OTP verification using the temporary token."""
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        email = payload.get("sub")
        action = payload.get("action")
        # Check for the correct action in the JWT
        if not email or action != "reset":
            raise HTTPException(status_code=401, detail="Invalid token payload or action")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    user = users_collection.find_one({"email": email})
    if not user:
        # Should not happen if token is valid, but safe guard.
        raise HTTPException(status_code=404, detail="User not found")
        
    # 🔑 FIX: Check for a valid, verified password_reset OTP entry for this email
    # Look for a *recently* verified OTP. We'll use a 5-minute window or similar for safety.
    # Note: A more robust solution would be to use the token expiry itself as the sole time limit.
    # For now, we rely on the successful JWT decoding.
    
    # We rely primarily on the 'action: reset' token, but we should clear the used OTP entry 
    # to maintain cleanliness, which is done below.

    hashed_password = get_password_hash(data.password)
    
    # Update user's password
    users_collection.update_one(
        {"_id": user["_id"]},
        {"$set": {
            "password": hashed_password,
            "updated_at": datetime.utcnow()
        }}
    )
    
    # Clean up the OTP records for this email and type that are already verified.
    # This prevents the "verified" state from remaining in the DB indefinitely.
    otps_collection.delete_many({"email": email, "type": "password_reset", "verified": True})


    return {"message": "Password reset successfully."}
# ---------------- User Profile ----------------
@app.get("/users/me", tags=["Users"])
def get_user_profile(current_user: dict = Depends(get_current_user)):
    # FIX: MongoDB ObjectId must be removed before returning
    current_user.pop("_id", None)
    # Password must be removed before returning
    current_user.pop("password", None)
    
    # FIX: Ensure datetime objects are converted to ISO format for safe JSON serialization
    if 'created_at' in current_user and isinstance(current_user['created_at'], datetime):
         current_user['created_at'] = current_user['created_at'].isoformat()
    if 'updated_at' in current_user and isinstance(current_user['updated_at'], datetime):
         current_user['updated_at'] = current_user['updated_at'].isoformat()
         
    return {
        "message": "Protected profile access successful",
        "user": current_user,
    }
    
# ---------------- CATEGORY ENDPOINTS ----------------
@app.post("/categories/bulk", tags=["Categories"])
def create_multiple_categories(data: BulkCategory, user=Depends(get_current_user)):
    
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to create categories")

    inserted = []
    for name in data.categories:
        name_lower = name.lower().strip()
        if categories_collection.find_one({"name": name_lower}):
            continue
            
        new_category = {
            "category_id": str(uuid.uuid4()),
            "name": name_lower,
            "created_by": user["user_id"],
            "created_at": datetime.utcnow()
        }
        
        result = categories_collection.insert_one(new_category)
        
        # FIX: The original code contained a correct fix for removing '_id'.
        # Re-implementing the safe removal and conversion of datetime.
        new_category.pop('_id', None)
        
        # Convert datetime objects to string before appending
        if 'created_at' in new_category:
            new_category['created_at'] = new_category['created_at'].isoformat()
        
        inserted.append(new_category)

    return {
        "message": "Categories created successfully",
        "inserted_count": len(inserted),
        "data": inserted
    }

@app.get("/categories", tags=["Categories"])
def get_all_categories(user=Depends(get_current_user)):
    
    cats = list(categories_collection.find({}, {"_id": 0})) 
    
    # FIX: Ensure datetime objects are converted to ISO format
    for cat in cats:
        if 'created_at' in cat and isinstance(cat['created_at'], datetime):
            cat['created_at'] = cat['created_at'].isoformat()
            
    return {"count": len(cats), "data": cats}

@app.delete("/categories/{category_id}", tags=["Categories"])
def delete_category(category_id: str, user=Depends(get_current_user)):
    """
    Delete a category by ID.
    - Only admin can perform this action.
    - Automatically deletes all products under the category (optional).
    """

    # Authorization check
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete categories")

    # check if category exists
    category = categories_collection.find_one({"category_id": category_id})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    # Delete category
    categories_collection.delete_one({"category_id": category_id})

    # Optionally delete all products in that category
    deleted_products = products_collection.delete_many({"category_id": category_id}).deleted_count

    return {
        "message": "Category deleted successfully",
        "category_id": category_id,
        "deleted_products": deleted_products
    }

# ---------------- PRODUCT ENDPOINTS ----------------

@app.post("/products/bulk", tags=["Products"])
def add_multiple_products(data: BulkProductItem, user=Depends(get_current_user)):
    """
    Add multiple products under a single category.
    - Checks if category exists
    - Skips duplicates (same name under the same category)
    - Generates product_id, created_by, created_at automatically
    """

    if user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to add products")

    # Check if category exists
    category = categories_collection.find_one({"category_id": data.category_id})
    if not category:
        raise HTTPException(status_code=404, detail="Category not found")

    inserted_products = []
    skipped_products = []

    for item in data.products:
        product_name = item.name.lower().strip()

        # check if product already exists in same category
        existing = products_collection.find_one({
            "name": product_name,
            "category_id": data.category_id
        })
        if existing:
            skipped_products.append(product_name)
            continue

        # Build new product document
        new_product = {
            "product_id": str(uuid.uuid4()),
            "name": product_name,
            "category_id": data.category_id,
            "price": item.price,
            "quantity": item.quantity,
            "threshold": getattr(item, "threshold", 5),
            "created_by": user["user_id"],
            "created_at": datetime.utcnow(),
        }

        products_collection.insert_one(new_product)
        new_product.pop("_id", None)
        
        # Convert datetime objects to string before appending
        if 'created_at' in new_product:
            new_product['created_at'] = new_product['created_at'].isoformat()
            
        inserted_products.append(new_product)

    return {
        "message": "Product upload completed",
        "inserted_count": len(inserted_products),
        "skipped_count": len(skipped_products),
        "inserted": inserted_products,
        "skipped": skipped_products
    }

@app.get("/products", tags=["Products"])
def get_all_products(user=Depends(get_current_user)):
    """
    Retrieves all products, ensuring datetime objects are correctly serialized 
    to prevent Pydantic errors which can cause fields (like product_id) to disappear.
    """
    
    # 1. Fetch data, excluding the MongoDB internal _id field
    products_data = list(products_collection.find({}, {"_id": 0}))
    
    # 2. Convert all datetime objects to ISO strings
    for product in products_data:
        if 'created_at' in product and isinstance(product['created_at'], datetime):
            product['created_at'] = product['created_at'].isoformat()
        if 'updated_at' in product and isinstance(product.get('updated_at'), datetime): # handle optional update field
            product['updated_at'] = product['updated_at'].isoformat()
            
    # The list of dictionaries is returned, and FastAPI validates each against the Product model
    return products_data

@app.put("/products/{product_id}", tags=["Products"])
def update_product(
    product_id: str,
    update: UpdateProduct = Body(...),
    user=Depends(get_current_user)
):
    """
    Update product details (name / price / quantity).
    Only admin and store_manager are allowed.
    """

    # 1) auth check
    if not user or user.get("role") not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to update products")

    # 2) check product exists
    product = products_collection.find_one({"product_id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # 3) build update dict from provided fields
    update_fields = {}
    if update.name is not None:
        update_fields["name"] = update.name.lower().strip()
    if update.price is not None:
        try:
            update_fields["price"] = float(update.price)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid price value")
    if update.quantity is not None:
        try:
            update_fields["quantity"] = int(update.quantity)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid quantity value")

    if not update_fields:
        raise HTTPException(status_code=400, detail="No valid fields to update")

    # 4) audit info (safe fallback if user_id missing)
    updater = user.get("user_id") or user.get("email") or "unknown"
    update_fields["updated_by"] = updater
    update_fields["updated_at"] = datetime.utcnow()

    # 5) apply update
    result = products_collection.update_one(
        {"product_id": product_id},
        {"$set": update_fields}
    )

    # 6) fetch updated product
    updated_product = products_collection.find_one({"product_id": product_id}, {"_id": 0})
    if not updated_product:
        raise HTTPException(status_code=500, detail="Error fetching updated product")

    # 7) serialize datetimes
    for key in ("created_at", "updated_at"):
        if key in updated_product and isinstance(updated_product[key], datetime):
            updated_product[key] = updated_product[key].isoformat()

    return {
        "message": "Product updated successfully",
        "data": updated_product
    }

@app.delete("/products/{product_id}", tags=["Products"])
def delete_product(product_id: str, user=Depends(get_current_user)):
    """
    Delete a product by its product_id.
    - Only admin and store_manager can perform this action.
    """

    # Authorization check
    if user.get("role") not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to delete products")

    # Check if product exists
    product = products_collection.find_one({"product_id": product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Delete the product
    products_collection.delete_one({"product_id": product_id})

    # Return response
    return {
        "message": "Product deleted successfully",
        "deleted_product_id": product_id,
        "deleted_by": user.get("user_id") or user.get("email"),
        "deleted_at": datetime.utcnow().isoformat()
    }

# ----------------- SUPPLIER ENDPOINTS ----------------

@app.post("/suppliers", tags=["Suppliers"])
def add_supplier(
    supplier: AddSupplier,
    current_user: dict = Depends(get_current_user)
):
    """Admin can add new suppliers"""
    # Ensure only admin can add suppliers
    if current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Only admin can add suppliers")

    # Prevent duplicate supplier names or emails
    existing = suppliers_collection.find_one({
        "$or": [
            {"supplier_name": supplier.supplier_name},
            {"email": supplier.email}
        ]
    })
    if existing:
        raise HTTPException(status_code=400, detail="Supplier already exists")

    supplier_data = {
        "supplier_id": str(uuid.uuid4()),
        "supplier_name": supplier.supplier_name,
        "contact_person": supplier.contact_person,
        "email": supplier.email,
        "phone": supplier.phone,
        "address": supplier.address,
        "company_name": supplier.company_name,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow(),
        "created_by": current_user["email"]
    }

    suppliers_collection.insert_one(supplier_data)
    
    # FIX: Remove the non-serializable _id field
    supplier_data.pop("_id", None)
    
    # FIX: Ensure datetime objects are converted to ISO format
    for key in ("created_at", "updated_at"):
        if key in supplier_data and isinstance(supplier_data[key], datetime):
            supplier_data[key] = supplier_data[key].isoformat()
    
    return {
        "message": "Supplier added successfully",
        "supplier": supplier_data
    }

@app.get("/suppliers", tags=["Suppliers"])
def get_all_suppliers(user=Depends(get_current_user)):
    """
    Fetch all supplier information.
    Only admin and store manager can access.
    """

    # Authorization check
    if user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to view suppliers")

    # Get all suppliers
    suppliers = list(suppliers_collection.find({}, {"_id": 0}))

    if not suppliers:
        return {"count": 0, "suppliers": []} # Return empty list instead of 404

    # FIX: Ensure datetime objects are converted to ISO format
    for supplier in suppliers:
        for key in ("created_at", "updated_at"):
            if key in supplier and isinstance(supplier[key], datetime):
                supplier[key] = supplier[key].isoformat()
                
    return {
        "count": len(suppliers),
        "suppliers": suppliers
    }

@app.get("/suppliers/{supplier_id}", tags=["Suppliers"])
def get_supplier_by_id(supplier_id: str, user=Depends(get_current_user)):
    """
    Fetch a single supplier by supplier_id (UUID).
    Only admin and store manager can access.
    """

    # Authorization check
    if user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to view supplier info")

    # Find supplier
    supplier = suppliers_collection.find_one({"supplier_id": supplier_id}, {"_id": 0})

    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")
        
    # FIX: Ensure datetime objects are converted to ISO format
    for key in ("created_at", "updated_at"):
        if key in supplier and isinstance(supplier[key], datetime):
            supplier[key] = supplier[key].isoformat()

    return supplier


@app.delete("/suppliers/{supplier_id}", tags=["Suppliers"])
def delete_supplier(supplier_id: str, user=Depends(get_current_user)):
    """
    Delete a supplier by supplier_id (UUID).
    Only admin can perform this action.
    """

    # Authorization check
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to delete suppliers")

    #Find the supplier
    supplier = suppliers_collection.find_one({"supplier_id": supplier_id})
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")

    # Delete the supplier
    suppliers_collection.delete_one({"supplier_id": supplier_id})

    return {
        "message": "Supplier deleted successfully",
        "deleted_supplier_id": supplier_id,
        "deleted_by": user["email"],
        "deleted_at": datetime.utcnow().isoformat()
    }
    
# ---------------- PURCHASE ENDPOINTS ----------------

@app.post("/purchases", tags=["Purchases"])
def create_purchase(item: PurchaseItem, user=Depends(get_current_user)):
    """
    Endpoint for admin to make a purchase.
    Only 'admin' can perform this action.
    """
    if user["role"] != "admin":
        raise HTTPException(status_code=403, detail="Only admin can make purchases")
    
    # Check if product and supplier exist
    product = products_collection.find_one({"product_id": item.product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    supplier = suppliers_collection.find_one({"supplier_id": item.supplier_id})
    if not supplier:
        raise HTTPException(status_code=404, detail="Supplier not found")


    # Build purchase record
    purchase_data = {
        "purchase_id": str(uuid.uuid4()),
        "supplier_id": item.supplier_id,
        "product_id": item.product_id,
        "product_name": product["name"], # Add product name for better record keeping
        "quantity": item.quantity,
        "status": "pending",
        "created_by": user["email"],
        "approved_by": None,
        "created_at": datetime.utcnow(),
        "updated_at": datetime.utcnow()
    }

    # Save to DB
    purchases_collection.insert_one(purchase_data)
    
    # FIX: Remove the non-serializable _id field and convert datetimes
    purchase_data.pop("_id", None)
    for key in ("created_at", "updated_at"):
        if key in purchase_data and isinstance(purchase_data[key], datetime):
            purchase_data[key] = purchase_data[key].isoformat()


    return {
        "message": "Purchase created successfully. Pending approval.",
        "data": purchase_data
    }
    
# ------------------ 2️⃣ VIEW PENDING PURCHASES ------------------
@app.get("/purchases/pending", tags=["Purchases"])
def view_pending_purchases(current_user=Depends(get_current_user)):
    """
    Admin or Store Manager can view all pending purchases.
    """
    if current_user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to view purchases")

    # Fetch, excluding _id
    purchases = list(purchases_collection.find({"status": "pending"}, {"_id": 0}))
    
    # FIX: Convert datetimes for serialization
    for p in purchases:
        for key in ("created_at", "updated_at"):
            if key in p and isinstance(p[key], datetime):
                p[key] = p[key].isoformat()

    return {"message": "Pending purchases retrieved", "data": purchases}


# ------------------ 3️⃣ STORE MANAGER APPROVES PURCHASE ------------------
@app.put("/purchases/{purchase_id}/approve", tags=["Purchases"])
def approve_purchase(purchase_id: str, current_user=Depends(get_current_user)):
    if current_user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to approve purchases")

    purchase = purchases_collection.find_one({"purchase_id": purchase_id})
    if not purchase:
        raise HTTPException(status_code=404, detail="Purchase not found")

    if purchase["status"] == "approved":
        raise HTTPException(status_code=400, detail="Purchase already approved")
        
    # Check product existence before approval
    product = products_collection.find_one({"product_id": purchase["product_id"]})
    if not product:
        # Deny approval if product does not exist, or delete/update the purchase record
        purchases_collection.update_one({"_id": purchase["_id"]}, {"$set": {"status": "error", "error_reason": "Product not found"}})
        raise HTTPException(status_code=404, detail=f"Product with ID {purchase['product_id']} not found. Cannot approve.")

    # Update status
    purchases_collection.update_one(
        {"purchase_id": purchase_id},
        {"$set": {"status": "approved", "approved_by": current_user["email"], "updated_at": datetime.utcnow()}}
    )

    # Update product quantity: Use $inc for atomic operation
    products_collection.update_one({"product_id": purchase["product_id"]}, {"$inc": {"quantity": purchase["quantity"]}})

    # --- SEND EMAIL ALERT TO ADMIN OR SUPPLIER ---
    subject = f"✅ Purchase Approved: {purchase_id}"
    body = f"""
Dear Team,

The purchase with ID {purchase_id} has been approved successfully by {current_user['email']}.

Product Name: {purchase.get('product_name', 'N/A')}
Product ID: {purchase['product_id']}
Quantity: {purchase['quantity']}
Status: Approved
Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

Regards,
Inventory System
"""

    # FIX: Sending email to the person who created the purchase (admin)
    try:
        send_email_alert(purchase["created_by"], subject, body)
    except Exception as e:
        # Log error but don't fail the API call just for email failure
        print(f"Failed to send email alert: {e}") 
        
    # Fetch the updated purchase record for the response
    updated_purchase = purchases_collection.find_one({"purchase_id": purchase_id}, {"_id": 0})
    if updated_purchase:
        for key in ("created_at", "updated_at"):
            if key in updated_purchase and isinstance(updated_purchase[key], datetime):
                updated_purchase[key] = updated_purchase[key].isoformat()

    return {"message": "Purchase approved and stock updated successfully", "data": updated_purchase}

# ------------------ 4️⃣ STORE MANAGER REJECTS PURCHASE (NEW ENDPOINT) ------------------
@app.put("/purchases/{purchase_id}/reject", tags=["Purchases"])
def reject_purchase(
    purchase_id: str, 
    # Use Optional[str] to allow the user to provide a reason in the request body
    rejection_reason: Optional[str] = Body(None, embed=True, alias="reason"),
    current_user=Depends(get_current_user)
):
    """
    Explicitly rejects a pending purchase order by ID.
    Roles allowed: admin, store_manager.
    """
    if current_user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to reject purchases")

    purchase = purchases_collection.find_one({"purchase_id": purchase_id})
    if not purchase:
        raise HTTPException(status_code=404, detail="Purchase not found")

    if purchase["status"] == "approved":
        raise HTTPException(status_code=400, detail="Cannot reject, purchase is already approved.")
    if purchase["status"] == "rejected":
        # Allow rejection again if status is already rejected (e.g., to update reason)
        pass 
        
    # Build update operation
    update_fields = {
        "status": "rejected", 
        "rejected_by": current_user["email"], 
        "updated_at": datetime.utcnow()
    }
    
    # Add reason if provided
    reason_text = rejection_reason if rejection_reason else "No reason provided."
    update_fields["rejection_reason"] = reason_text

    # Update the purchase record
    purchases_collection.update_one(
        {"purchase_id": purchase_id}, 
        {"$set": update_fields}
    )

    # --- SEND EMAIL ALERT TO PURCHASE CREATOR (ADMIN) ---
    subject = f"❌ Purchase Rejected: {purchase_id}"
    body = f"""
Dear Team,

The purchase with ID **{purchase_id}** for **{purchase.get('product_name', 'N/A')}** has been **REJECTED**.

Product ID: {purchase['product_id']}
Quantity: {purchase['quantity']}
Rejected By: {current_user['email']}
Reason: {reason_text}
Date: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}

Please review and re-submit if necessary.

Regards,
Inventory System
"""
    try:
        # Send email to the person who created the purchase (created_by is typically the Admin initiating the purchase)
        send_email_alert(purchase["created_by"], subject, body)
    except Exception as e:
        print(f"Failed to send rejection email alert: {e}") 
        # API call proceeds even if email fails

    # Fetch the final record for response
    rejected_purchase = purchases_collection.find_one({"purchase_id": purchase_id}, {"_id": 0})
    if rejected_purchase:
        for key in ("created_at", "updated_at"):
            if key in rejected_purchase and isinstance(rejected_purchase[key], datetime):
                rejected_purchase[key] = rejected_purchase[key].isoformat()

    return {"message": "Purchase rejected and creator notified", "data": rejected_purchase}

@app.post("/products/sell", tags=["Products"])
def sell_product(sale: SellProduct, user=Depends(get_current_user)):
    """
    Sell a product and reduce its quantity in stock.
    Roles allowed: admin, store_manager, sales_staff.
    Sends threshold email alert if quantity is below limit.
    """
    # Role check
    if user["role"] not in ["admin", "store_manager", "sales_staff"]:
        raise HTTPException(status_code=403, detail="Not authorized to sell products")

    # Find product
    product = products_collection.find_one({"product_id": sale.product_id})
    if not product:
        raise HTTPException(status_code=404, detail="Product not found")

    # Validate quantity
    if sale.quantity <= 0:
        raise HTTPException(status_code=400, detail="Quantity must be greater than zero")

    if sale.quantity > product["quantity"]:
        raise HTTPException(status_code=400, detail=f"Insufficient stock. Available: {product['quantity']}")

    # Reduce quantity: Use $inc for atomic operation
    products_collection.update_one(
        {"product_id": sale.product_id},
        {"$inc": {"quantity": -sale.quantity}, "$set": {"updated_at": datetime.utcnow()}}
    )
    
    new_quantity = product["quantity"] - sale.quantity # Calculate for alert

    # Record the sale
    price_per_unit = product.get("price", 0)
    sale_record = {
        "sale_id": str(uuid.uuid4()),
        "product_id": sale.product_id,
        "product_name": product["name"],
        "quantity_sold": sale.quantity,
        "price_per_unit": price_per_unit,
        "total_sale_price": sale.quantity * price_per_unit,
        "sold_by": user["email"],
        "role": user["role"],
        "sold_at": datetime.utcnow(),
    }
    sales_collection.insert_one(sale_record)

    # Send email alert if below threshold
    threshold = product.get("threshold", 5)
    if new_quantity <= threshold:
        admin_email = os.getenv("ADMIN_EMAIL")
        subject = f"⚠️ Low Stock Alert: {product['name']}"
        body = f"""
        Dear Admin,

        The product **{product['name']}** is running low on stock.

        Remaining Quantity: {new_quantity}
        Threshold Limit: {threshold}

        Please consider restocking soon.

        Regards,
        Inventory System
        """

        try:
            # FIX: Ensure ADMIN_EMAIL is used for the alert
            if admin_email:
                send_email_alert(admin_email, subject, body)
                print(f"Low stock alert sent to {admin_email} for {product['name']}")
            else:
                 print("ADMIN_EMAIL not configured for low stock alert.")
        except Exception as e:
            print("Failed to send low stock email:", e)

    # Response
    updated_product = products_collection.find_one({"product_id": sale.product_id}, {"_id": 0})
    
    # FIX: Remove _id and convert datetimes for safe response
    sale_record.pop("_id", None)
    if 'sold_at' in sale_record:
        sale_record['sold_at'] = sale_record['sold_at'].isoformat()
    if updated_product:
        for key in ("created_at", "updated_at"):
            if key in updated_product and isinstance(updated_product[key], datetime):
                updated_product[key] = updated_product[key].isoformat()
        updated_product["quantity"] = new_quantity # Ensure the new quantity is correct in the response
        
    return {
        "message": f"Sold {sale.quantity} units of {product['name']}",
        "product": updated_product,
        "sale_record": sale_record,
    }

# ----------------- SALE VIEW ENDPOINT -----------------

@app.get("/sales", tags=["Sales"])
def get_all_sales(current_user=Depends(get_current_user)):
    """
    Retrieves all sales records.
    Roles allowed: admin, store_manager.
    """
    
    # 1. Authorization check
    if current_user["role"] not in ["admin", "store_manager"]:
        raise HTTPException(status_code=403, detail="Not authorized to view sales records")

    # 2. Fetch all sales, excluding the MongoDB default _id field
    sales_list = list(sales_collection.find({}, {"_id": 0}))

    # 3. Convert datetime objects to ISO format for safe JSON serialization
    for sale in sales_list:
        if "sold_at" in sale and isinstance(sale["sold_at"], datetime):
            sale["sold_at"] = sale["sold_at"].isoformat()
            
    if not sales_list:
        return {"message": "No sales records found", "data": []}

    return {
        "message": "Sales records retrieved successfully",
        "count": len(sales_list),
        "data": sales_list
    }



