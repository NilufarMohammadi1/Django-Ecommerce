from django.shortcuts import render
from store.models import Product
from category.models import Category
from carts.models import Cart,CartItem
from carts.views import _cart_id

def home(request):
    products = Product.objects.all().filter()
    
    cats = Category.objects.all()
    

 
    context = {
        'products': products,
        'cats':cats,
        
    }
    return render(request, 'home.html',context)