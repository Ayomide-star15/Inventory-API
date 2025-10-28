from pydantic import BaseModel, EmailStr, Field
from typing import Optional, List, Union
from datetime import datetime

class RegisterUser(BaseModel):

    first_name: str
    last_name: str 
    email: EmailStr
    role: str 
    phone_number: str 
    address:str
    state: str
    country: str


class VerifyOTP(BaseModel):
    otp: str

class CreatePassword(BaseModel):
    password: str

class ForgotPassword(BaseModel):
    email: EmailStr

class ResetPassword(BaseModel):
    password: str

class OTPOnly(BaseModel):
    otp: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

# ---------------- CATEGORY MODELS --------------

# ---------------- CATEGORY MODELS --------------

class BulkCategory(BaseModel):
    categories: List[str]

# Category response model
class Category(BaseModel):
    category_id: str
    name: str
    created_by: str
    created_at: datetime

# Product model (as provided in your code)
class Product(BaseModel):
    name: str
    quantity: int
    price: float
    threshold: int = 5
    

class BulkProductItem(BaseModel):
    category_id: str
    products: List[Product]

class UpdateProduct(BaseModel):
    name: Optional[str] = None
    quantity: Optional[int] = None
    price: Optional[float] = None


class AddSupplier(BaseModel):
    supplier_name: str
    contact_person: Optional[str] = None
    email: Optional[EmailStr] = None
    phone: Optional[str] = None
    address: Optional[str] = None
    company_name: Optional[str] = None

class PurchaseItem(BaseModel):
    supplier_id: str
    product_id: str
    quantity: int


class SellProduct(BaseModel):
    product_id: str
    quantity: int

class UpdateSupplier(BaseModel):
    name: Optional[str] = Field(None, description="Supplier name")
    contact_person: Optional[str] = Field(None, description="Person to contact")
    phone: Optional[str] = Field(None, description="Phone number")
    email: Optional[EmailStr] = Field(None, description="Supplier email")
    address: Optional[str] = Field(None, description="Supplier address")

class UpdateUserProfile(BaseModel):
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    phone_number: Optional[str] = None
    address: Optional[str] = None
    state: Optional[str] = None
    country: Optional[str] = None

class UpdateUserRole(BaseModel):
    user_id: str
    role: str
