# Database Migration Guide

## Overview

This guide covers database migration procedures for SecureSys Auditor, including forward migrations, rollback strategies, and data integrity verification.

## Migration Strategy

### Development vs Production

| Environment | Strategy | Backup Required |
|------------|----------|----------------|
| **Development** | Fresh tables (drop & recreate) | No |
| **Staging** | Scripted migration with verification | Yes |
| **Production** | Scripted migration with canary testing | Yes (automated) |

## Migration Command

### Basic Usage

```bash
# Preview migration (dry run)
python manage.py migrate_scanning_data --dry-run

# Perform migration with backup
python manage.py migrate_scanning_data --backup

# Verify data integrity
python manage.py migrate_scanning_data --verify
```

### Options

- `--dry-run`: Preview changes without committing to database
- `--backup`: Create JSON backup before migration
- `--rollback`: Rollback migration (copy data from scanning back to core)
- `--verify`: Verify data integrity after migration

## Migration Process

### Step 1: Pre-Migration Checklist

1. **Backup Database**
   ```bash
   # Automated backup (recommended)
   python manage.py migrate_scanning_data --backup
   
   # Manual PostgreSQL backup
   pg_dump -U securesys_user -h localhost securesys_db > backup_$(date +%Y%m%d_%H%M%S).sql
   ```

2. **Check Current State**
   ```bash
   python manage.py showmigrations
   ```

3. **Verify Application Health**
   - Ensure all services are running
   - Check for any pending background jobs
   - Review recent error logs

### Step 2: Run Migration

```bash
# 1. Dry run to preview
python manage.py migrate_scanning_data --dry-run

# 2. If dry run looks good, execute migration
python manage.py migrate_scanning_data --backup

# 3. Verify data integrity
python manage.py migrate_scanning_data --verify
```

### Step 3: Post-Migration Verification

1. **Check Record Counts**
   ```python
   from scanning.models import System, Scan, Finding, Recommendation
   
   print(f"Systems: {System.objects.count()}")
   print(f"Scans: {Scan.objects.count()}")
   print(f"Findings: {Finding.objects.count()}")
   print(f"Recommendations: {Recommendation.objects.count()}")
   ```

2. **Run Integration Tests**
   ```bash
   pytest tests/test_migration.py -v
   ```

3. **Test Critical Workflows**
   - Submit a new scan via agent
   - View scans in frontend
   - Check webhook deliveries

## Rollback Procedures

### Scenario 1: Migration Failed During Execution

**The migration command automatically rolls back on failure** due to transaction management.

```bash
# Check application logs
tail -f logs/django.log

# Verify database state
python manage.py dbshell
\dt scanning_*
```

### Scenario 2: Migration Succeeded but Data Issues Found

1. **Restore from JSON Backup**
   ```bash
   # The backup file is in backups/migration_backup_YYYYMMDD_HHMMSS.json
   python manage.py migrate_scanning_data --rollback
   ```

2. **Restore from PostgreSQL Backup**
   ```bash
   # Stop application
   docker-compose down
   
   # Restore database
   psql -U securesys_user -h localhost securesys_db < backup_20231223_143022.sql
   
   # Restart application
   docker-compose up -d
   ```

### Scenario 3: Need to Revert to Core Models

If you need to go back to using core app models:

1. **Copy Data Back to Core Tables**
   ```bash
   python manage.py migrate_scanning_data --rollback
   ```

2. **Update Code References**
   - Change imports from `scanning.models` back to `core.models`
   - Update serializers and views
   - Run tests

3. **Apply Core Migrations**
   ```bash
   python manage.py migrate core
   ```

## Migration in CI/CD

### Pre-Deployment Steps

1. **Run Migration in Staging**
   ```yaml
   - name: Run database migration
     run: |
       python manage.py migrate_scanning_data --backup --verify
   ```

2. **Automated Tests**
   ```yaml
   - name: Run migration tests
     run: |
       pytest tests/test_migration.py --cov
   ```

### Deployment with Migration

```yaml
deploy:
  script:
    # 1. Create backup
    - python manage.py migrate_scanning_data --backup
    
    # 2. Run migrations
    - python manage.py migrate
    
    # 3. Migrate data
    - python manage.py migrate_scanning_data
    
    # 4. Verify
    - python manage.py migrate_scanning_data --verify
    
    # 5. Run smoke tests
    - python manage.py test tests.smoke
```

### Canary Deployment Strategy

For production, use a canary deployment:

1. **Deploy to 10% of infrastructure**
2. **Run migration on canary database**
3. **Monitor for 1 hour**
   - Error rates
   - Response times
   - Data integrity checks
4. **If successful, deploy to remaining 90%**
5. **If failed, rollback canary deployment**

## Data Integrity Checks

### Automated Checks

The migration command includes built-in verification:

```bash
python manage.py migrate_scanning_data --verify
```

This checks:
- Record counts match between core and scanning tables
- Foreign key relationships are intact
- No orphaned records
- Data types are correct

### Manual Verification Queries

```sql
-- Check for missing systems
SELECT COUNT(*) FROM core_system 
WHERE id NOT IN (SELECT id FROM scanning_systems);

-- Check for missing scans
SELECT COUNT(*) FROM core_scan 
WHERE id NOT IN (SELECT id FROM scanning_scans);

-- Verify relationships
SELECT s.id, s.hostname, COUNT(sc.id) as scan_count
FROM scanning_systems s
LEFT JOIN scanning_scans sc ON s.id = sc.system_id
GROUP BY s.id, s.hostname
ORDER BY scan_count DESC;
```

## Troubleshooting

### Issue: Migration Hangs

**Cause**: Large dataset or database locks

**Solution**:
1. Check for long-running queries: `SELECT * FROM pg_stat_activity;`
2. Kill blocking queries if safe
3. Run migration during maintenance window

### Issue: Foreign Key Violations

**Cause**: Orphaned records or constraint issues

**Solution**:
```sql
-- Find orphaned scans
SELECT * FROM scanning_scans 
WHERE system_id NOT IN (SELECT id FROM scanning_systems);

-- Clean up (if appropriate)
DELETE FROM scanning_scans 
WHERE system_id NOT IN (SELECT id FROM scanning_systems);
```

### Issue: Out of Memory

**Cause**: Processing too many records at once

**Solution**: Modify the migration command to process in batches:
```python
# In migrate_scanning_data.py
for system in core_models.System.objects.iterator(chunk_size=1000):
    # migrate system
```

## Best Practices

1. **Always backup before migration** (automated via `--backup` flag)
2. **Test migration in staging first**
3. **Run during low-traffic periods**
4. **Monitor application metrics** during and after migration
5. **Keep multiple backup generations**
6. **Document any manual steps** taken during migration
7. **Have rollback plan ready** before starting
8. **Verify data integrity** after migration completes

## Emergency Contacts

In case of production migration issues:

1. Database Team: dba@company.com
2. DevOps Team: devops@company.com
3. On-Call Engineer: [PagerDuty/Slack]

## Backup Retention

- **Development**: 7 days
- **Staging**: 30 days
- **Production**: 90 days + archival

Backups are stored in:
- JSON backups: `backups/migration_backup_*.json`
- PostgreSQL dumps: Managed by automated backup system
- Cloud backups: S3/GCS (production only)

## Migration Checklist

- [ ] Review migration code
- [ ] Test in development environment
- [ ] Create database backup
- [ ] Run migration in staging
- [ ] Verify data integrity
- [ ] Run integration tests
- [ ] Update documentation
- [ ] Communicate to team
- [ ] Schedule production migration
- [ ] Execute production migration
- [ ] Verify production data
- [ ] Monitor for 24 hours
- [ ] Archive migration artifacts
