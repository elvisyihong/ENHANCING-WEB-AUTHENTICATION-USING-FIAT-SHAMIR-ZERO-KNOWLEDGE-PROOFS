from django.contrib.auth import authenticate, login as django_login, logout as django_logout
from django.contrib.auth.models import User
from .models import Profile
from django.views.decorators.csrf import csrf_exempt
from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.http import JsonResponse
import hashlib, random

@csrf_exempt
def login_view(request):
    if request.method == "POST":
        auth_type = request.POST.get('auth_type')
        username = request.POST.get('username')
        password = request.POST.get('password')

        print("\n===== Login Attempt =====")
        print("Auth Type:", auth_type)
        print("Username:", username)
        print("Password:", password)

        if auth_type == 'django':
            user = authenticate(request, username=username, password=password)
            if user:
                django_login(request, user)
                return redirect('home')
            else:
                return render(request, 'login.html', {'error': 'Invalid data or User not found'})

        elif auth_type == 'plaintext':
            try:
                user = User.objects.get(username=username)
                if user.profile.raw_password == password:
                    django_login(request, user)
                    return redirect('home')
                else:
                    return render(request, 'login.html', {'error': 'Invalid data or User not found'})
            except User.DoesNotExist:
                return render(request, 'login.html', {'error': 'Invalid data or User not found'})

        elif auth_type == 'zk':
            p = 0xFFFFFFFEFFFFFC2F
            g = 2
            try:
                commitment = int(request.POST.get('commitment'))
                response = int(request.POST.get('response'))
                print("Commitment received:", commitment)
                print("Response received:", response)
            except (TypeError, ValueError):
                print("Failed to parse commitment or response.")
                return JsonResponse({'success': False, 'error': 'Invalid data'})

            user = User.objects.filter(username=username).first()
            if not user:
                print("ZK user not found.")
                return JsonResponse({'success': False, 'error': 'User not found'})

            zk_pubkey = int(user.profile.zk_pubkey)
            print("Retrieved zk_pubkey (from database):", zk_pubkey)

            # Retrieve the stored challenge nonce
            challenge_nonce = request.session.get(f'zk_challenge_{username}')
            if not challenge_nonce:
                print("Challenge nonce not found or expired.")
                return JsonResponse({'success': False, 'error': 'Challenge expired or not found'})
            print("Challenge nonce (from session):", challenge_nonce)

            lhs = pow(g, response, p)
            rhs = (commitment * pow(int(zk_pubkey), int(challenge_nonce), p)) % p
            print("===== Verifying proof =====")
            print("LHS (g^response % p):", lhs)
            print("RHS (commitment * pubkey^challenge % p):", rhs)
            if lhs == rhs:
                print("ZK Proof verified successfully.")
                del request.session[f'zk_challenge_{username}']
                request.session.modified = True
                django_login(request, user)
                return JsonResponse({'success': True})
            else:
                print("ZK Proof verification failed.")
                return JsonResponse({'success': False, 'error': 'Invalid data or User not found'})

        else:
            return render(request, 'login.html', {'error': 'Invalid authentication type.'})

    return render(request, 'login.html')

@csrf_exempt
def register(request):
    if request.method == 'POST':
        auth_type = request.POST.get('auth_type')  # "zk", "django", or "plain"
        username = request.POST.get('username')
        password = request.POST.get('password')  # used for django/plain
        zk_pubkey = request.POST.get('zk_pubkey')  # used for zk only

        if not username or not auth_type:
            return JsonResponse({'success': False, 'error': 'Missing required fields'})

        if User.objects.filter(username=username).exists():
            return JsonResponse({'success': False, 'error': 'Username already exists'})

        # Create user
        if auth_type == 'zk':
            if not zk_pubkey:
                return JsonResponse({'success': False, 'error': 'Missing ZK public key'})
            user = User.objects.create_user(username=username)  # no password
            Profile.objects.create(user=user, zk_pubkey=zk_pubkey)

        elif auth_type == 'django':
            if not password:
                return JsonResponse({'success': False, 'error': 'Missing password'})
            user = User.objects.create_user(username=username, password=password)
            Profile.objects.create(user=user, zk_pubkey='')  # optional

        elif auth_type == 'plaintext':
            if not password:
                return JsonResponse({'success': False, 'error': 'Missing plaintext password'})
            user = User.objects.create_user(username=username)  # Django still needs to store hashed password
            Profile.objects.create(user=user, raw_password=password)

        else:
            return JsonResponse({'success': False, 'error': 'Invalid authentication type'})

        return JsonResponse({'success': True})

    return render(request, 'register.html')

def zk_challenge(request):
    username = request.GET.get("username")
    commitment = request.GET.get("commitment")
    print("\n===== Challenge Request =====")
    print("Username:", username)
    print("Commitment:", commitment)

    if not username or not commitment:
        print("Missing username or commitment.")
        return JsonResponse({"success": False, "error": "Missing data"})

    try:
        p = 0xFFFFFFFEFFFFFC2F
        # Use a server-side nonce, like a random 128-bit int
        server_nonce = random.getrandbits(128)
        print("Generated server nonce:", server_nonce)
        challenge = int(hashlib.sha256(f"{commitment}{server_nonce}".encode()).hexdigest(), 16) % p
        print("Computed challenge (hash):", challenge)
        # Save challenge in session
        request.session[f'zk_challenge_{username}'] = str(challenge)
        request.session['zk_commitment'] = commitment
        print("Challenge saved in session.")
        return JsonResponse({"success": True, "challenge": str(challenge)})
    except:
        print("Error in challenge generation:")
        return JsonResponse({"success": False, "error": "Internal error"})

@login_required
def home(request):
    # Simple home page view, user must be logged in
    return render(request, 'home.html', {'user': request.user})

def logout(request):
    django_logout(request)
    return redirect('login')  # Redirect to your login page