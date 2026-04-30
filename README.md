CVE-2026-31431, aka "copy fail". Write data to an existing file regardless of user permissions.

Use this to check whether you kernel is compromised.

```
mkdir -p protected
echo old > protected/target
sudo chown -R root protected
echo new | tee protected/target # expected to fail

echo new | ./supertee.py protected/target
cat protected/target
```

Note the payload "new\n" is the same size as curent file contents "old\n". If the payload were larger, supertee.py would hang.
