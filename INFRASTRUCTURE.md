# Guía de Infraestructura - gologin 🏗️

## Agnosticismo de Infraestructura

El paquete `gologin` está diseñado para ser **completamente agnóstico** de tu infraestructura mediante el uso de **interfaces**. Puedes usar cualquier tecnología de almacenamiento o caché.

---

## 🔌 Interfaces Disponibles

### 1. UserRepository
```go
type UserRepository interface {
    Save(user *User) error
    FindByUsername(username string) (*User, error)
    FindByID(id string) (*User, error)
    IsUsernameTaken(username string) (bool, error)
}
```

### 2. RateLimiter
```go
type RateLimiter interface {
    Allow(identifier string) bool
    Reset(identifier string)
}
```

### 3. TokenBlacklist
```go
type TokenBlacklist interface {
    Add(tokenID string, expiresAt time.Time) error
    IsBlacklisted(tokenID string) bool
    Remove(tokenID string) error
}
```

---

## 📦 Implementaciones de Ejemplo

### PostgreSQL + Redis (Recomendado para Producción)

```go
package infrastructure

import (
    "context"
    "database/sql"
    "time"
    
    "github.com/go-redis/redis/v8"
    _ "github.com/lib/pq"
    "your-project/gologin"
)

// PostgreSQL UserRepository
type PostgresUserRepository struct {
    db *sql.DB
}

func NewPostgresUserRepository(db *sql.DB) *PostgresUserRepository {
    return &PostgresUserRepository{db: db}
}

func (r *PostgresUserRepository) Save(user *gologin.User) error {
    if user.ID == nil {
        // Insert
        query := `
            INSERT INTO users (owner_id, owner_type, username, password_hash, created_at)
            VALUES ($1, $2, $3, $4, $5)
            RETURNING id
        `
        var id string
        err := r.db.QueryRow(query, user.OwnerID, user.OwnerType, 
            user.Username, user.PasswordHash, user.CreatedAt).Scan(&id)
        if err != nil {
            return err
        }
        user.ID = &id
        return nil
    }
    
    // Update
    query := `
        UPDATE users 
        SET owner_id = $1, owner_type = $2, username = $3, 
            password_hash = $4, created_at = $5
        WHERE id = $6
    `
    _, err := r.db.Exec(query, user.OwnerID, user.OwnerType, 
        user.Username, user.PasswordHash, user.CreatedAt, *user.ID)
    return err
}

func (r *PostgresUserRepository) FindByUsername(username string) (*gologin.User, error) {
    user := &gologin.User{}
    var id string
    
    query := `
        SELECT id, owner_id, owner_type, username, password_hash, created_at
        FROM users WHERE username = $1
    `
    
    err := r.db.QueryRow(query, username).Scan(
        &id, &user.OwnerID, &user.OwnerType, 
        &user.Username, &user.PasswordHash, &user.CreatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    user.ID = &id
    return user, nil
}

func (r *PostgresUserRepository) FindByID(id string) (*gologin.User, error) {
    user := &gologin.User{}
    var userID string
    
    query := `
        SELECT id, owner_id, owner_type, username, password_hash, created_at
        FROM users WHERE id = $1
    `
    
    err := r.db.QueryRow(query, id).Scan(
        &userID, &user.OwnerID, &user.OwnerType, 
        &user.Username, &user.PasswordHash, &user.CreatedAt,
    )
    
    if err == sql.ErrNoRows {
        return nil, nil
    }
    if err != nil {
        return nil, err
    }
    
    user.ID = &userID
    return user, nil
}

func (r *PostgresUserRepository) IsUsernameTaken(username string) (bool, error) {
    var count int
    query := `SELECT COUNT(*) FROM users WHERE username = $1`
    err := r.db.QueryRow(query, username).Scan(&count)
    return count > 0, err
}

// Redis Rate Limiter
type RedisRateLimiter struct {
    client      *redis.Client
    maxAttempts int
    window      time.Duration
    ctx         context.Context
}

func NewRedisRateLimiter(client *redis.Client, maxAttempts int, window time.Duration) *RedisRateLimiter {
    return &RedisRateLimiter{
        client:      client,
        maxAttempts: maxAttempts,
        window:      window,
        ctx:         context.Background(),
    }
}

func (r *RedisRateLimiter) Allow(identifier string) bool {
    key := "ratelimit:" + identifier
    
    // Increment counter
    count, err := r.client.Incr(r.ctx, key).Result()
    if err != nil {
        return false // Fail closed
    }
    
    // Set expiry on first attempt
    if count == 1 {
        r.client.Expire(r.ctx, key, r.window)
    }
    
    return count <= int64(r.maxAttempts)
}

func (r *RedisRateLimiter) Reset(identifier string) {
    key := "ratelimit:" + identifier
    r.client.Del(r.ctx, key)
}

// Redis Token Blacklist
type RedisTokenBlacklist struct {
    client *redis.Client
    ctx    context.Context
}

func NewRedisTokenBlacklist(client *redis.Client) *RedisTokenBlacklist {
    return &RedisTokenBlacklist{
        client: client,
        ctx:    context.Background(),
    }
}

func (r *RedisTokenBlacklist) Add(tokenID string, expiresAt time.Time) error {
    key := "blacklist:" + tokenID
    ttl := time.Until(expiresAt)
    
    if ttl <= 0 {
        return nil // Already expired
    }
    
    return r.client.Set(r.ctx, key, "1", ttl).Err()
}

func (r *RedisTokenBlacklist) IsBlacklisted(tokenID string) bool {
    key := "blacklist:" + tokenID
    result, err := r.client.Exists(r.ctx, key).Result()
    return err == nil && result > 0
}

func (r *RedisTokenBlacklist) Remove(tokenID string) error {
    key := "blacklist:" + tokenID
    return r.client.Del(r.ctx, key).Err()
}

// Inicialización completa
func SetupAuthService() (gologin.AuthService, error) {
    // PostgreSQL
    db, err := sql.Open("postgres", "postgres://user:pass@localhost/dbname?sslmode=disable")
    if err != nil {
        return nil, err
    }
    
    // Redis
    redisClient := redis.NewClient(&redis.Options{
        Addr:     "localhost:6379",
        Password: "",
        DB:       0,
    })
    
    // Repositories
    userRepo := NewPostgresUserRepository(db)
    loginLimiter := NewRedisRateLimiter(redisClient, 5, 15*time.Minute)
    registerLimiter := NewRedisRateLimiter(redisClient, 3, 1*time.Hour)
    blacklist := NewRedisTokenBlacklist(redisClient)
    
    // JWT Secret from environment
    jwtSecret := os.Getenv("JWT_SECRET")
    
    return gologin.NewAuthServiceWithOptions(
        userRepo,
        jwtSecret,
        blacklist,
        loginLimiter,
        registerLimiter,
    ), nil
}
```

---

### MongoDB + Memcached

```go
package infrastructure

import (
    "context"
    "time"
    
    "github.com/bradfitz/gomemcache/memcache"
    "go.mongodb.org/mongo-driver/bson"
    "go.mongodb.org/mongo-driver/mongo"
    "your-project/gologin"
)

// MongoDB UserRepository
type MongoUserRepository struct {
    collection *mongo.Collection
    ctx        context.Context
}

func NewMongoUserRepository(client *mongo.Client, database, collection string) *MongoUserRepository {
    return &MongoUserRepository{
        collection: client.Database(database).Collection(collection),
        ctx:        context.Background(),
    }
}

func (r *MongoUserRepository) Save(user *gologin.User) error {
    if user.ID == nil {
        // Insert
        result, err := r.collection.InsertOne(r.ctx, bson.M{
            "owner_id":      user.OwnerID,
            "owner_type":    user.OwnerType,
            "username":      user.Username,
            "password_hash": user.PasswordHash,
            "created_at":    user.CreatedAt,
        })
        if err != nil {
            return err
        }
        id := result.InsertedID.(string)
        user.ID = &id
        return nil
    }
    
    // Update
    filter := bson.M{"_id": *user.ID}
    update := bson.M{"$set": bson.M{
        "owner_id":      user.OwnerID,
        "owner_type":    user.OwnerType,
        "username":      user.Username,
        "password_hash": user.PasswordHash,
        "created_at":    user.CreatedAt,
    }}
    
    _, err := r.collection.UpdateOne(r.ctx, filter, update)
    return err
}

func (r *MongoUserRepository) FindByUsername(username string) (*gologin.User, error) {
    var user gologin.User
    err := r.collection.FindOne(r.ctx, bson.M{"username": username}).Decode(&user)
    if err == mongo.ErrNoDocuments {
        return nil, nil
    }
    return &user, err
}

func (r *MongoUserRepository) FindByID(id string) (*gologin.User, error) {
    var user gologin.User
    err := r.collection.FindOne(r.ctx, bson.M{"_id": id}).Decode(&user)
    if err == mongo.ErrNoDocuments {
        return nil, nil
    }
    return &user, err
}

func (r *MongoUserRepository) IsUsernameTaken(username string) (bool, error) {
    count, err := r.collection.CountDocuments(r.ctx, bson.M{"username": username})
    return count > 0, err
}

// Memcached Rate Limiter
type MemcachedRateLimiter struct {
    client      *memcache.Client
    maxAttempts int
    window      time.Duration
}

func NewMemcachedRateLimiter(servers []string, maxAttempts int, window time.Duration) *MemcachedRateLimiter {
    return &MemcachedRateLimiter{
        client:      memcache.New(servers...),
        maxAttempts: maxAttempts,
        window:      window,
    }
}

func (r *MemcachedRateLimiter) Allow(identifier string) bool {
    key := "ratelimit:" + identifier
    
    // Try to get current count
    item, err := r.client.Get(key)
    if err == memcache.ErrCacheMiss {
        // First attempt
        r.client.Set(&memcache.Item{
            Key:        key,
            Value:      []byte("1"),
            Expiration: int32(r.window.Seconds()),
        })
        return true
    }
    
    count := len(item.Value)
    if count >= r.maxAttempts {
        return false
    }
    
    // Increment
    newValue := append(item.Value, '1')
    r.client.Set(&memcache.Item{
        Key:        key,
        Value:      newValue,
        Expiration: int32(r.window.Seconds()),
    })
    
    return true
}

func (r *MemcachedRateLimiter) Reset(identifier string) {
    key := "ratelimit:" + identifier
    r.client.Delete(key)
}
```

---

### DynamoDB + ElastiCache (AWS)

```go
package infrastructure

import (
    "time"
    
    "github.com/aws/aws-sdk-go/aws"
    "github.com/aws/aws-sdk-go/service/dynamodb"
    "github.com/aws/aws-sdk-go/service/dynamodb/dynamodbattribute"
    "your-project/gologin"
)

// DynamoDB UserRepository
type DynamoDBUserRepository struct {
    client    *dynamodb.DynamoDB
    tableName string
}

func NewDynamoDBUserRepository(client *dynamodb.DynamoDB, tableName string) *DynamoDBUserRepository {
    return &DynamoDBUserRepository{
        client:    client,
        tableName: tableName,
    }
}

func (r *DynamoDBUserRepository) Save(user *gologin.User) error {
    item, err := dynamodbattribute.MarshalMap(user)
    if err != nil {
        return err
    }
    
    input := &dynamodb.PutItemInput{
        TableName: aws.String(r.tableName),
        Item:      item,
    }
    
    _, err = r.client.PutItem(input)
    return err
}

func (r *DynamoDBUserRepository) FindByUsername(username string) (*gologin.User, error) {
    input := &dynamodb.QueryInput{
        TableName:              aws.String(r.tableName),
        IndexName:              aws.String("username-index"),
        KeyConditionExpression: aws.String("username = :username"),
        ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
            ":username": {S: aws.String(username)},
        },
    }
    
    result, err := r.client.Query(input)
    if err != nil {
        return nil, err
    }
    
    if len(result.Items) == 0 {
        return nil, nil
    }
    
    var user gologin.User
    err = dynamodbattribute.UnmarshalMap(result.Items[0], &user)
    return &user, err
}

// ... FindByID, IsUsernameTaken similar
```

---

## 🎯 Recomendaciones por Escenario

### Desarrollo Local
```go
// Usa implementaciones in-memory (ya incluidas)
authService := gologin.NewAuthService(
    NewMockUserRepository(),
    "dev-secret-key-32-characters-long",
)
```

### Producción Pequeña/Mediana (< 100k usuarios)
- **Base de datos**: PostgreSQL o MySQL
- **Caché**: Redis standalone
- **Rate Limiting**: Redis
- **Costo**: ~$50-200/mes

### Producción Grande (> 100k usuarios)
- **Base de datos**: PostgreSQL con réplicas o Aurora
- **Caché**: Redis Cluster o ElastiCache
- **Rate Limiting**: Redis Cluster
- **Costo**: $500+/mes

### Serverless (AWS Lambda, Cloud Run)
- **Base de datos**: DynamoDB, Firestore, o PlanetScale
- **Caché**: ElastiCache, Memorystore, o Upstash Redis
- **Rate Limiting**: DynamoDB con TTL o API Gateway throttling
- **Consideración**: Conexiones de DB limitadas

---

## ✅ Checklist de Implementación

- [ ] Implementar `UserRepository` para tu base de datos
- [ ] Implementar `RateLimiter` con tu sistema de caché
- [ ] Implementar `TokenBlacklist` con tu sistema de caché
- [ ] Configurar índices en la base de datos (username, id)
- [ ] Configurar TTL automático para tokens expirados
- [ ] Testing con datos reales en staging
- [ ] Monitoreo de latencia de caché
- [ ] Plan de respaldo si caché falla (graceful degradation)

---

## 🔄 Migración entre Infraestructuras

El sistema te permite cambiar de infraestructura sin modificar la lógica de negocio:

```go
// Antes: In-Memory
authService := gologin.NewAuthService(mockRepo, secret)

// Después: PostgreSQL + Redis (solo cambias las implementaciones)
authService := gologin.NewAuthServiceWithOptions(
    postgresRepo,
    secret,
    redisBlacklist,
    redisLoginLimiter,
    redisRegisterLimiter,
)

// La API permanece igual ✅
user, err := authService.RegisterUser(...)
resp, err := authService.Login(...)
```

---

## 📚 Ejemplos Completos

Ver carpeta `/examples` para implementaciones completas:
- `examples/postgres-redis/` - Setup completo con Docker Compose
- `examples/mongodb/` - Implementación con MongoDB
- `examples/serverless-aws/` - Lambda + DynamoDB + ElastiCache
- `examples/gcp/` - Cloud Run + Cloud SQL + Memorystore

---

## 🆘 Soporte

¿Necesitas ayuda implementando para una infraestructura específica? Abre un issue en GitHub con el tag `infrastructure`.
