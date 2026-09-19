from django.contrib.auth.models import User
from django.core.management.base import BaseCommand

from vulnerable_app.models import Order, Profile

# Lab-only credentials, intentionally simple and documented in the README --
# this project never runs anywhere but a developer's own machine.
LAB_PASSWORD = "lab-password-123"


class Command(BaseCommand):
    help = "Seeds the vulnerable lab with demo users (alice, bob) and orders."

    def handle(self, *args, **options):
        alice, created_alice = User.objects.get_or_create(
            username="alice", defaults={"email": "alice@lab.local"}
        )
        if created_alice:
            alice.set_password(LAB_PASSWORD)
            alice.save()

        bob, created_bob = User.objects.get_or_create(
            username="bob", defaults={"email": "bob@lab.local"}
        )
        if created_bob:
            bob.set_password(LAB_PASSWORD)
            bob.save()

        Order.objects.get_or_create(
            owner=alice,
            item_name="Alice's private laptop order",
            defaults={"amount": "1299.00", "note": "Should only be visible to alice"},
        )
        Order.objects.get_or_create(
            owner=bob,
            item_name="Bob's private phone order",
            defaults={"amount": "899.00", "note": "Should only be visible to bob"},
        )

        Profile.objects.get_or_create(
            user=alice, defaults={"bio": "Hi, I'm Alice.", "role": "user"}
        )
        Profile.objects.get_or_create(user=bob, defaults={"bio": "Hi, I'm Bob.", "role": "user"})

        self.stdout.write(self.style.SUCCESS("Lab seeded: users alice/bob, 1 order each."))
        self.stdout.write(f"Password for both accounts: {LAB_PASSWORD}")
