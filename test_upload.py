# test_upload.py

import cloudinary
import cloudinary.uploader

cloudinary.config(
    cloud_name='dxm5scbpw',
    api_key='798278373751285',
    api_secret='-FS_NRNlGTylyBoGr8yZaI7lN9M',
)

# Test upload
try:
    result = cloudinary.uploader.upload('resumes/resumes/cv.pdf')
    print(result)
except Exception as e:
    print(f"Error: {e}")
