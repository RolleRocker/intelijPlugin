package com.example.oauthplugin.actions;

import com.example.oauthplugin.auth.AuthService;
import com.intellij.openapi.progress.ProgressIndicator;
import com.intellij.openapi.progress.Task;
import com.intellij.openapi.project.Project;
import org.jetbrains.annotations.NotNull;
import org.jetbrains.annotations.Nullable;

import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Shows a cancellable "waiting for sign-in" background progress while a
 * login is in flight, so the user isn't left with no feedback for up to
 * LOGIN_TIMEOUT_SECONDS if they don't finish in the browser.
 */
public final class LoginProgress {

    private LoginProgress() {
    }

    /** @param project may be null (e.g. shown from an application-level settings page) */
    public static void show(@Nullable Project project, AuthService authService, CompletableFuture<Void> loginFuture) {
        new Task.Backgroundable(project, "Waiting for OAuth Sign-In", true) {
            @Override
            public void run(@NotNull ProgressIndicator indicator) {
                indicator.setText("Complete sign-in in your browser, or cancel to abort.");
                while (!loginFuture.isDone()) {
                    if (indicator.isCanceled()) {
                        authService.cancelLogin();
                        return;
                    }
                    try {
                        loginFuture.get(200, TimeUnit.MILLISECONDS);
                    } catch (TimeoutException ignored) {
                        // Not done yet - loop back around to check cancellation again.
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        return;
                    } catch (ExecutionException e) {
                        // Failure is reported to the user by the caller's own
                        // whenComplete() callback on loginFuture.
                        return;
                    }
                }
            }
        }.queue();
    }
}
