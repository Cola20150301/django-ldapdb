# -*- coding: utf-8 -*-
# This software is distributed under the two-clause BSD license.
# Copyright (c) The django-ldapdb project

from __future__ import unicode_literals

import datetime
import re

from django.db.models import fields, lookups
from django.utils import timezone


class LdapLookup(lookups.Lookup):
    def _as_ldap(self, lhs, rhs):
        raise NotImplementedError()

    def process_lhs(self, compiler, connection):
        return (self.lhs.target.column, [])

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        params = lhs_params + rhs_params
        return self._as_ldap(lhs, rhs), params


class ContainsLookup(LdapLookup):
    lookup_name = 'contains'

    def _as_ldap(self, lhs, rhs):
        return '%s=*%s*' % (lhs, rhs)


class IContainsLookup(ContainsLookup):
    lookup_name = 'icontains'


class StartsWithLookup(LdapLookup):
    lookup_name = 'startswith'

    def _as_ldap(self, lhs, rhs):
        return '%s=%s*' % (lhs, rhs)


class EndsWithLookup(LdapLookup):
    lookup_name = 'endswith'

    def _as_ldap(self, lhs, rhs):
        return '%s=*%s' % (lhs, rhs)


class ExactLookup(LdapLookup):
    lookup_name = 'exact'

    def _as_ldap(self, lhs, rhs):
        return '%s=%s' % (lhs, rhs)


class GteLookup(LdapLookup):
    lookup_name = 'gte'

    def _as_ldap(self, lhs, rhs):
        return '%s>=%s' % (lhs, rhs)


class LteLookup(LdapLookup):
    lookup_name = 'lte'

    def _as_ldap(self, lhs, rhs):
        return '%s<=%s' % (lhs, rhs)


class InLookup(LdapLookup):
    lookup_name = 'in'
    rhs_is_iterable = True

    def as_sql(self, compiler, connection):
        lhs, lhs_params = self.process_lhs(compiler, connection)
        rhs, rhs_params = self.process_rhs(compiler, connection)
        params = lhs_params + rhs_params
        return '|' + ''.join('(%s=%s)' % (lhs, '%s') for _p in rhs_params), params

    def get_prep_lookup(self):
        return self.rhs

    def get_db_prep_lookup(self, value, connection):
        if self.rhs_is_iterable:
            return (
                ['%s'] * len(value),
                [self.lhs.output_field.get_db_prep_value(v, connection, prepared=True) for v in value]
            )
        else:
            return (
                '%s',
                [self.lhs.output_field.get_db_prep_value(value, connection, prepared=True)],
            )


class ListContainsLookup(ExactLookup):
    lookup_name = 'contains'


class BaseDateTimeLookup(object):
    def get_db_prep_lookup(self, value, connection):
        return (
            '%s',
            [self.lhs.output_field.get_db_prep_value(value, connection, prepared=True)[0].decode(connection.charset)],
        )


class DateTimeExactLookup(BaseDateTimeLookup, ExactLookup):
    pass


class DateTimeGteLookup(BaseDateTimeLookup, GteLookup):
    pass


class DateTimeLteLookup(BaseDateTimeLookup, LteLookup):
    pass


class CharField(fields.CharField):
    def __init__(self, *args, **kwargs):
        defaults = {'max_length': 200}
        defaults.update(kwargs)
        super(CharField, self).__init__(*args, **defaults)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return ''
        else:
            return value[0].decode(connection.charset)

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        return [value.encode(connection.charset)]


CharField.register_lookup(ContainsLookup)
CharField.register_lookup(IContainsLookup)
CharField.register_lookup(StartsWithLookup)
CharField.register_lookup(EndsWithLookup)
CharField.register_lookup(InLookup)
CharField.register_lookup(ExactLookup)


class ImageField(fields.Field):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return ''
        else:
            return value[0]

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        return [value]


ImageField.register_lookup(ExactLookup)


class IntegerField(fields.IntegerField):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return 0
        else:
            return int(value[0])

    def get_db_prep_save(self, value, connection):
        if value is None:
            return None
        return [str(value).encode(connection.charset)]


IntegerField.register_lookup(ExactLookup)
IntegerField.register_lookup(GteLookup)
IntegerField.register_lookup(LteLookup)
IntegerField.register_lookup(InLookup)


class FloatField(fields.FloatField):
    def from_ldap(self, value, connection):
        if len(value) == 0:
            return 0.0
        else:
            return float(value[0])

    def get_db_prep_save(self, value, connection):
        if value is None:
            return None
        return [str(value).encode(connection.charset)]


FloatField.register_lookup(ExactLookup)
FloatField.register_lookup(GteLookup)
FloatField.register_lookup(LteLookup)
FloatField.register_lookup(InLookup)


class ListField(fields.Field):

    def from_ldap(self, value, connection):
        return [x.decode(connection.charset) for x in value]

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        return [x.encode(connection.charset) for x in value]

    def from_db_value(self, value, expression, connection, context):
        """Convert from the database format.

        This should be the inverse of self.get_prep_value()
        """
        return self.to_python(value)

    def to_python(self, value):
        if not value:
            return []
        return value


ListField.register_lookup(ListContainsLookup)


class DateField(fields.DateField):
    """
    A text field containing date, in specified format.
    The format can be specified as 'format' argument, as strptime()
    format string. It defaults to ISO8601 (%Y-%m-%d).

    Note: 'lte' and 'gte' lookups are done string-wise. Therefore,
    they will onlywork correctly on Y-m-d dates with constant
    component widths.
    """

    def __init__(self, *args, **kwargs):
        if 'format' in kwargs:
            self._date_format = kwargs.pop('format')
        else:
            self._date_format = '%Y-%m-%d'
        super(DateField, self).__init__(*args, **kwargs)

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return None
        else:
            return datetime.datetime.strptime(value[0].decode(connection.charset),
                                              self._date_format).date()

    def get_db_prep_save(self, value, connection):
        if not value:
            return None
        if not isinstance(value, datetime.date) \
                and not isinstance(value, datetime.datetime):
            raise ValueError(
                'DateField can be only set to a datetime.date instance')

        return [value.strftime(self._date_format).encode(connection.charset)]


DateField.register_lookup(ExactLookup)


LDAP_DATETIME_RE = re.compile(
    r'(?P<year>\d{4})'
    r'(?P<month>\d{2})'
    r'(?P<day>\d{2})'
    r'(?P<hour>\d{2})'
    r'(?P<minute>\d{2})?'
    r'(?P<second>\d{2})?'
    r'(?:[.,](?P<microsecond>\d+))?'
    r'(?P<tzinfo>Z|[+-]\d{2}(?:\d{2})?)'
    r'$'
)


LDAP_DATE_FORMAT = '%Y%m%d%H%M%S.%fZ'


def datetime_from_ldap(value):
    """Convert a LDAP-style datetime to a Python aware object.

    See https://tools.ietf.org/html/rfc4517#section-3.3.13 for details.

    Args:
        value (str): the datetime to parse
    """
    if not value:
        return None
    match = LDAP_DATETIME_RE.match(value)
    if not match:
        return None
    groups = match.groupdict()
    if groups['microsecond']:
        groups['microsecond'] = groups['microsecond'].ljust(6, '0')[:6]
    tzinfo = groups.pop('tzinfo')
    if tzinfo == 'Z':
        tzinfo = timezone.utc
    else:
        offset_mins = int(tzinfo[-2:]) if len(tzinfo) == 5 else 0
        offset = 60 * int(tzinfo[1:3]) + offset_mins
        if tzinfo[0] == '-':
            offset = - offset
        tzinfo = timezone.get_fixed_timezone(offset)
    kwargs = {k: int(v) for k, v in groups.items() if v is not None}
    kwargs['tzinfo'] = tzinfo
    return datetime.datetime(**kwargs)


class DateTimeField(fields.DateTimeField):
    """
    A file containing a UTC timestamp, in uTCTimeSyntax syntax.

    That syntax is ``YYYYmmddHH[MM[SS[.ff](Z|+XX[YY]|-XX[YY])``.
    """

    def from_ldap(self, value, connection):
        if len(value) == 0:
            return None
        return datetime_from_ldap(value[0].decode(connection.charset))

    def get_db_prep_value(self, value, connection, prepared=False):
        if not value:
            return None
        if not isinstance(value, datetime.date) \
                and not isinstance(value, datetime.datetime):
            raise ValueError(
                'DateField can be only set to a datetime.date instance')

        value = timezone.utc.normalize(value)
        return [value.strftime(LDAP_DATE_FORMAT).encode(connection.charset)]


DateTimeField.register_lookup(DateTimeExactLookup)
DateTimeField.register_lookup(DateTimeLteLookup)
DateTimeField.register_lookup(DateTimeGteLookup)
