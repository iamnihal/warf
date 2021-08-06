"""wapf URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from django.conf import settings
from django.conf.urls.static import static
from scanEngine.views import (
    subdomain_finder,
    index,
    about,
    directory_brute_force,
    waybackurls,
    js_urls,
    js_secrets,
    js_links,
    full_scan,
    fullscan_result,
    download_result,
    setting_wordlist,
    ajax_call,
    target_view,
    scan_result,
    download_target_result,
    scan_view,
    dash_scan,
    scan_search,
    target_delete,
    fullscan_overview,
)
from users.views import register, profile, dashboard, add_target, target, target_bookmark, bookmark_view
from django.contrib.auth import views as auth_views

urlpatterns = [
    # Scan URLs
    path("admin/", admin.site.urls),
    path("", index, name="index-page"),
    path("about/", about, name="about-page"),
    path("scan/subdomain/", subdomain_finder, name="subdomain-page"),
    path("scan/directory/", directory_brute_force, name="directory-page"),
    path("scan/wayback/", waybackurls, name="wayback-page"),
    path("scan/jsurl/", js_urls, name="jsurl-page"),
    path("scan/secret/", js_secrets, name="secret-page"),
    path("scan/endpoint/", js_links, name="endpoint-page"),
    # Download URLs
    path("download/", download_result, name="download-result"),
    path("download/<int:pk>/", download_target_result, name="download-target-result"),
    # Fullscan URLs
    path("scan/fullscan/", full_scan, name="fullscan-page"),
    path("fullscan/", fullscan_result, name="fullscan"),
    path("fullscan/", fullscan_result, name="fullscan-subdomain"),
    path("fullscan/", fullscan_result, name="fullscan-directory"),
    path("fullscan/", fullscan_result, name="fullscan-wayback"),
    path("fullscan/", fullscan_result, name="fullscan-jsurl"),
    path("fullscan/", fullscan_result, name="fullscan-secrets"),
    path("fullscan/", fullscan_result, name="fullscan-linkfinder"),
    # Settings
    path("setting/wordlist/", setting_wordlist, name="wordlist-page"),
    # Ajax
    path("scan/ajax/", ajax_call, name="ajax-call"),
    # Login/Register/Logout
    path("register/", register, name="register"),
    path(
        "login/",
        auth_views.LoginView.as_view(template_name="users/login.html"),
        name="login",
    ),
    path(
        "logout/",
        auth_views.LogoutView.as_view(template_name="users/logout.html"),
        name="logout",
    ),
    path(
        "begin_password_reset/",
        auth_views.PasswordResetView.as_view(template_name="users/password-reset.html"),
        name="password-reset",
    ),
    path(
        "begin_password_reset/done/",
        auth_views.PasswordResetDoneView.as_view(template_name="users/password-reset-done.html"),
        name="password_reset_done",
    ),
    path(
        "password_reset_confirm/<uidb64>/<token>/",
        auth_views.PasswordResetConfirmView.as_view(template_name="users/password-reset-confirm.html"),
        name="password_reset_confirm",
    ),
    path(
        "password_reset_complete/",
        auth_views.PasswordResetCompleteView.as_view(template_name="users/password-reset-complete.html"),
        name="password_reset_complete",
    ),
    # Profile/Dashboard
    path("profile/", profile, name="profile"),
    path("dashboard/", dashboard, name="dashboard"),
    # Targets/Scans
    path("add-target/", add_target, name="add-target"),
    path("targets/", target, name="targets"),
    path("targets/<int:pk>/", target_view, name="target-view"),
    path("targets/<int:pk>/result/", scan_result, name="scan-result"),
    path("targets/<str:scantype>/overview/", scan_view, name="scan-view"),
    path("targets/delete/<int:pk>/", target_delete, name="target-delete"),
    path("scans/overview/", dash_scan, name="dash-scan"),
    path("scans/overview/search/", scan_search, name="scan-search"),
    path("targets/<int:pk>/bookmark/", target_bookmark, name="target-bookmark"),
    path("targets/bookmark/", bookmark_view, name="bookmark-view"),
    path("targets/<int:pk>/fullscan/result/", fullscan_overview, name="fullscan-overview"),
]

if settings.DEBUG:
    # urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)