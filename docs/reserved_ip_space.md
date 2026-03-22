# Lint `reserved_ip_space`

Found an IP in reserved IP space.
Reserved IP space, like RFC 1918 or documentation ranges, should never be seen on the public internet.
Thus any comparison with such an reserved IP address should usually evaluate to false and can indicate a typo or useless rule.
