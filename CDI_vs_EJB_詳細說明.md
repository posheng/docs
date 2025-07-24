# Java EE CDI vs EJB 詳細說明

## 1. 基本概念對比

### CDI (Contexts and Dependency Injection)
- **定義**: Java EE 的依賴注入標準，專注於物件的生命週期管理和依賴注入
- **核心功能**: 
  - 依賴注入 (Dependency Injection)
  - 上下文管理 (Context Management)
  - 事件處理 (Event Handling)
  - 裝飾器模式 (Decorator Pattern)
  - 攔截器 (Interceptors)

### EJB (Enterprise JavaBeans)
- **定義**: Java EE 的企業級組件模型，提供分散式、交易式、安全的企業應用框架
- **核心功能**:
  - 自動交易管理
  - 安全性管理
  - 並發控制
  - 生命週期管理
  - 遠端調用支援
  - 資源管理

## 2. 生命週期詳細對比

### CDI 生命週期範圍

```java
// @RequestScoped - 每個 HTTP 請求一個實例
@Named
@RequestScoped
public class RequestScopedBean {
    private String data;
    
    @PostConstruct
    public void init() {
        System.out.println("RequestScoped bean created");
        data = "Request-" + System.currentTimeMillis();
    }
    
    @PreDestroy
    public void cleanup() {
        System.out.println("RequestScoped bean destroyed");
    }
    
    public String getData() {
        return data;
    }
}

// @SessionScoped - 每個 HTTP 會話一個實例
@Named
@SessionScoped
@Serializable
public class SessionScopedBean implements Serializable {
    private String userPreference;
    private List<String> shoppingCart = new ArrayList<>();
    
    @PostConstruct
    public void init() {
        System.out.println("SessionScoped bean created");
    }
    
    public void addToCart(String item) {
        shoppingCart.add(item);
    }
    
    // Getters and setters...
}

// @ApplicationScoped - 整個應用程式一個實例
@ApplicationScoped
public class ApplicationScopedBean {
    private final Map<String, Object> cache = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void init() {
        System.out.println("ApplicationScoped bean created");
        loadConfiguration();
    }
    
    private void loadConfiguration() {
        // 載入應用程式配置
    }
    
    public void putCache(String key, Object value) {
        cache.put(key, value);
    }
    
    public Object getCache(String key) {
        return cache.get(key);
    }
}

// @ConversationScoped - 跨多個請求的對話範圍
@Named
@ConversationScoped
@Serializable
public class ConversationScopedBean implements Serializable {
    
    @Inject
    private Conversation conversation;
    
    private String conversationData;
    
    public void startConversation() {
        if (conversation.isTransient()) {
            conversation.begin();
            System.out.println("Conversation started: " + conversation.getId());
        }
    }
    
    public void endConversation() {
        if (!conversation.isTransient()) {
            conversation.end();
            System.out.println("Conversation ended");
        }
    }
    
    // Getters and setters...
}
```

### EJB 生命週期類型

```java
// @Stateless - 無狀態，每次調用可能是不同實例
@Stateless
@LocalBean
public class StatelessEJB {
    
    @PersistenceContext
    private EntityManager em;
    
    @PostConstruct
    public void init() {
        System.out.println("Stateless EJB created");
    }
    
    @PreDestroy
    public void cleanup() {
        System.out.println("Stateless EJB destroyed");
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public User createUser(String name, String email) {
        User user = new User(name, email);
        em.persist(user);
        return user;
    }
    
    public List<User> findAllUsers() {
        return em.createQuery("SELECT u FROM User u", User.class)
                 .getResultList();
    }
}

// @Stateful - 有狀態，維護客戶端會話狀態
@Stateful
@LocalBean
public class StatefulEJB {
    
    private String clientId;
    private List<String> userActions = new ArrayList<>();
    
    @PostConstruct
    public void init() {
        System.out.println("Stateful EJB created");
        clientId = "Client-" + System.currentTimeMillis();
    }
    
    @PreDestroy
    public void cleanup() {
        System.out.println("Stateful EJB destroyed for client: " + clientId);
    }
    
    public void recordAction(String action) {
        userActions.add(action + " at " + new Date());
    }
    
    public List<String> getActionHistory() {
        return new ArrayList<>(userActions);
    }
    
    @Remove // 客戶端調用此方法後，EJB 實例會被移除
    public void logout() {
        System.out.println("User logged out, removing stateful EJB");
    }
}

// @Singleton - 單例，整個應用程式一個實例
@Singleton
@Startup // 應用程式啟動時立即創建
@LocalBean
public class SingletonEJB {
    
    private final AtomicInteger counter = new AtomicInteger(0);
    private final Map<String, Object> applicationCache = new ConcurrentHashMap<>();
    
    @PostConstruct
    public void init() {
        System.out.println("Singleton EJB created at startup");
        loadSystemConfiguration();
    }
    
    @Lock(LockType.READ) // 允許並發讀取
    public int getCounter() {
        return counter.get();
    }
    
    @Lock(LockType.WRITE) // 排他寫入
    public int increment() {
        return counter.incrementAndGet();
    }
    
    @Schedule(minute = "*/5", hour = "*") // 每 5 分鐘執行一次
    public void scheduledTask() {
        System.out.println("Scheduled task executed at: " + new Date());
    }
    
    private void loadSystemConfiguration() {
        // 載入系統配置
    }
}
```

## 3. 交易管理詳細對比

### CDI 交易管理

```java
// CDI 需要手動管理交易或使用 @Transactional (JTA 1.2+)
@RequestScoped
public class CDITransactionService {
    
    @Inject
    private EntityManager em;
    
    @Inject
    private UserTransaction userTransaction;
    
    // 手動交易管理
    public void manualTransactionExample() {
        try {
            userTransaction.begin();
            
            User user = new User("John", "john@example.com");
            em.persist(user);
            
            // 模擬業務邏輯
            processUserRegistration(user);
            
            userTransaction.commit();
        } catch (Exception e) {
            try {
                userTransaction.rollback();
            } catch (SystemException se) {
                throw new RuntimeException("Rollback failed", se);
            }
            throw new RuntimeException("Transaction failed", e);
        }
    }
    
    // 使用 @Transactional 注解 (JTA 1.2+)
    @Transactional(value = Transactional.TxType.REQUIRED, 
                   rollbackOn = {Exception.class})
    public void declarativeTransactionExample() {
        User user = new User("Jane", "jane@example.com");
        em.persist(user);
        
        // 如果這裡拋出異常，交易會自動回滾
        processUserRegistration(user);
    }
    
    private void processUserRegistration(User user) {
        // 業務邏輯處理
    }
}
```

### EJB 交易管理

```java
@Stateless
public class EJBTransactionService {
    
    @PersistenceContext
    private EntityManager em;
    
    // 預設是 REQUIRED，自動交易管理
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    public void requiredTransaction() {
        User user = new User("Bob", "bob@example.com");
        em.persist(user);
        // 交易自動管理，方法結束時自動提交
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void requiresNewTransaction() {
        // 總是開始新交易，即使調用者已經在交易中
        User user = new User("Alice", "alice@example.com");
        em.persist(user);
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    public User findUser(Long id) {
        // 如果調用者有交易則參與，沒有則不開啟交易
        return em.find(User.class, id);
    }
    
    @TransactionAttribute(TransactionAttributeType.NEVER)
    public void utilityMethod() {
        // 如果調用者有交易則拋出異常
        // 適用於工具方法
    }
    
    // 複雜的交易場景
    public void complexBusinessProcess() {
        try {
            createUser();
            updateInventory();
            sendNotification();
        } catch (Exception e) {
            // EJB 容器會自動回滾整個交易
            throw new EJBException("Business process failed", e);
        }
    }
    
    private void createUser() {
        // 子操作 1
    }
    
    private void updateInventory() {
        // 子操作 2
    }
    
    private void sendNotification() {
        // 子操作 3
    }
}
```

## 4. 安全性管理

### CDI 安全性

```java
@RequestScoped
public class CDISecurityService {
    
    @Inject
    private Principal principal;
    
    @Inject
    private HttpServletRequest request;
    
    public boolean isUserInRole(String role) {
        return request.isUserInRole(role);
    }
    
    public String getCurrentUser() {
        return principal != null ? principal.getName() : "anonymous";
    }
    
    // 自定義安全檢查
    public void checkPermission(String operation) {
        if (!hasPermission(operation)) {
            throw new SecurityException("Access denied for operation: " + operation);
        }
    }
    
    private boolean hasPermission(String operation) {
        // 自定義權限邏輯
        String username = getCurrentUser();
        return checkUserPermissions(username, operation);
    }
    
    private boolean checkUserPermissions(String username, String operation) {
        // 查詢資料庫或快取檢查權限
        return true; // 簡化實作
    }
}
```

### EJB 安全性

```java
@Stateless
@RolesAllowed({"admin", "manager", "user"})
public class EJBSecurityService {
    
    @Resource
    private SessionContext sessionContext;
    
    @RolesAllowed({"admin"})
    public void adminOnlyOperation() {
        System.out.println("Admin operation executed by: " + 
                          sessionContext.getCallerPrincipal().getName());
    }
    
    @RolesAllowed({"admin", "manager"})
    public void managerOperation() {
        String caller = sessionContext.getCallerPrincipal().getName();
        
        if (sessionContext.isCallerInRole("admin")) {
            // 管理員有額外權限
            performAdminActions();
        }
        
        performManagerActions();
    }
    
    @PermitAll
    public String getPublicInfo() {
        return "This is public information";
    }
    
    @DenyAll
    public void restrictedOperation() {
        // 沒有人可以調用此方法
    }
    
    // 程式化安全檢查
    public void dynamicSecurityCheck(String operation) {
        String caller = sessionContext.getCallerPrincipal().getName();
        
        if (!hasPermissionForOperation(caller, operation)) {
            throw new EJBAccessException("Access denied for " + caller);
        }
        
        // 執行操作
    }
    
    private boolean hasPermissionForOperation(String caller, String operation) {
        // 動態權限檢查邏輯
        return true;
    }
    
    private void performAdminActions() {
        // 管理員專用操作
    }
    
    private void performManagerActions() {
        // 管理者操作
    }
}
```

## 5. 依賴注入模式

### CDI 高級依賴注入

```java
// 1. 限定符號 (Qualifiers)
@Qualifier
@Retention(RUNTIME)
@Target({METHOD, FIELD, PARAMETER, TYPE})
public @interface DatabaseType {
    DatabaseTypeEnum value();
}

public enum DatabaseTypeEnum {
    MYSQL, POSTGRESQL, ORACLE
}

// 不同的資料庫實作
@DatabaseType(DatabaseTypeEnum.MYSQL)
@ApplicationScoped
public class MySQLUserDAO implements UserDAO {
    public void save(User user) {
        // MySQL 特定實作
    }
}

@DatabaseType(DatabaseTypeEnum.POSTGRESQL)
@ApplicationScoped  
public class PostgreSQLUserDAO implements UserDAO {
    public void save(User user) {
        // PostgreSQL 特定實作
    }
}

// 注入特定實作
@RequestScoped
public class UserService {
    
    @Inject
    @DatabaseType(DatabaseTypeEnum.MYSQL)
    private UserDAO mysqlDAO;
    
    @Inject
    @DatabaseType(DatabaseTypeEnum.POSTGRESQL)
    private UserDAO postgresDAO;
    
    // 動態選擇實作
    @Inject
    private Instance<UserDAO> daos;
    
    public void saveUser(User user, String dbType) {
        UserDAO dao = daos.select(new DatabaseTypeLiteral(dbType)).get();
        dao.save(user);
    }
}

// 2. 生產者方法 (Producer Methods)
@ApplicationScoped
public class ConfigurationProducer {
    
    @Produces
    @ApplicationScoped
    @ConfigProperty(name = "database.url")
    public String getDatabaseUrl() {
        return System.getProperty("database.url", "jdbc:h2:mem:testdb");
    }
    
    @Produces
    @ApplicationScoped
    public DataSource createDataSource(@ConfigProperty(name = "database.url") String url) {
        HikariConfig config = new HikariConfig();
        config.setJdbcUrl(url);
        config.setUsername("user");
        config.setPassword("password");
        return new HikariDataSource(config);
    }
}

// 3. 攔截器 (Interceptors)
@InterceptorBinding
@Retention(RUNTIME)
@Target({METHOD, TYPE})
public @interface Logged {
}

@Logged
@Interceptor
@Priority(Interceptor.Priority.APPLICATION)
public class LoggingInterceptor {
    
    @AroundInvoke
    public Object logMethodEntry(InvocationContext context) throws Exception {
        String methodName = context.getMethod().getName();
        String className = context.getTarget().getClass().getSimpleName();
        
        System.out.println("Entering method: " + className + "." + methodName);
        
        long startTime = System.currentTimeMillis();
        try {
            Object result = context.proceed();
            long endTime = System.currentTimeMillis();
            System.out.println("Method " + methodName + " completed in " + 
                             (endTime - startTime) + "ms");
            return result;
        } catch (Exception e) {
            System.out.println("Method " + methodName + " threw exception: " + 
                             e.getMessage());
            throw e;
        }
    }
}

// 使用攔截器
@RequestScoped
@Logged
public class BusinessService {
    
    public void performBusinessLogic() {
        // 這個方法會被記錄
        System.out.println("Executing business logic");
    }
}

// 4. 事件處理 (Events)
public class UserRegisteredEvent {
    private final User user;
    private final Date timestamp;
    
    public UserRegisteredEvent(User user) {
        this.user = user;
        this.timestamp = new Date();
    }
    
    // Getters...
}

@RequestScoped
public class UserRegistrationService {
    
    @Inject
    private Event<UserRegisteredEvent> userRegisteredEvent;
    
    public void registerUser(User user) {
        // 註冊用戶邏輯
        saveUser(user);
        
        // 觸發事件
        userRegisteredEvent.fire(new UserRegisteredEvent(user));
    }
    
    private void saveUser(User user) {
        // 保存用戶
    }
}

// 事件觀察者
@ApplicationScoped
public class UserEventHandler {
    
    public void onUserRegistered(@Observes UserRegisteredEvent event) {
        System.out.println("User registered: " + event.getUser().getName());
        
        // 發送歡迎郵件
        sendWelcomeEmail(event.getUser());
    }
    
    public void onUserRegisteredAsync(@ObservesAsync UserRegisteredEvent event) {
        // 異步處理
        processUserAnalytics(event.getUser());
    }
    
    private void sendWelcomeEmail(User user) {
        // 發送郵件邏輯
    }
    
    private void processUserAnalytics(User user) {
        // 分析處理
    }
}
```

### EJB 依賴注入

```java
// EJB 注入方式
@Stateless
public class OrderServiceEJB {
    
    // 注入其他 EJB
    @EJB
    private UserServiceEJB userService;
    
    @EJB
    private InventoryServiceEJB inventoryService;
    
    // 注入資源
    @PersistenceContext
    private EntityManager em;
    
    @Resource
    private SessionContext sessionContext;
    
    @Resource(lookup = "java:global/MyDataSource")
    private DataSource dataSource;
    
    // 注入 CDI Bean
    @Inject
    private EmailService emailService;
    
    public Order processOrder(Order order) {
        // 使用注入的服務
        User user = userService.findUser(order.getUserId());
        boolean available = inventoryService.checkAvailability(order.getItems());
        
        if (available) {
            em.persist(order);
            emailService.sendOrderConfirmation(user, order);
        }
        
        return order;
    }
}

// 遠端 EJB 介面
@Remote
public interface RemoteOrderService {
    Order processOrder(Order order);
    List<Order> findOrdersByUser(Long userId);
}

@Stateless
public class RemoteOrderServiceEJB implements RemoteOrderService {
    
    @Override
    public Order processOrder(Order order) {
        // 遠端調用實作
        return order;
    }
    
    @Override
    public List<Order> findOrdersByUser(Long userId) {
        // 查詢實作
        return new ArrayList<>();
    }
}
```

## 6. 實際專案架構建議

### 分層架構範例

```java
// 1. 前端控制器層 (CDI)
@Named
@ViewScoped
@Serializable
public class ProductController implements Serializable {
    
    @EJB
    private ProductServiceEJB productService;
    
    @Inject
    private FacesContext facesContext;
    
    private Product selectedProduct = new Product();
    private List<Product> products;
    
    @PostConstruct
    public void init() {
        loadProducts();
    }
    
    public void loadProducts() {
        try {
            products = productService.findAllProducts();
        } catch (Exception e) {
            facesContext.addMessage(null, 
                new FacesMessage(FacesMessage.SEVERITY_ERROR, 
                "Error loading products", e.getMessage()));
        }
    }
    
    public String saveProduct() {
        try {
            if (selectedProduct.getId() == null) {
                productService.createProduct(selectedProduct);
            } else {
                productService.updateProduct(selectedProduct);
            }
            loadProducts();
            return "products?faces-redirect=true";
        } catch (Exception e) {
            facesContext.addMessage(null, 
                new FacesMessage(FacesMessage.SEVERITY_ERROR, 
                "Error saving product", e.getMessage()));
            return null;
        }
    }
    
    // Getters and setters...
}

// 2. 業務服務層 (EJB)
@Stateless
@LocalBean
public class ProductServiceEJB {
    
    @PersistenceContext
    private EntityManager em;
    
    @EJB
    private AuditServiceEJB auditService;
    
    @Inject
    private Event<ProductCreatedEvent> productCreatedEvent;
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @RolesAllowed({"admin", "manager"})
    public Product createProduct(Product product) {
        validateProduct(product);
        
        product.setCreatedDate(new Date());
        product.setCreatedBy(getCurrentUser());
        
        em.persist(product);
        
        // 觸發事件
        productCreatedEvent.fire(new ProductCreatedEvent(product));
        
        // 審計記錄
        auditService.logAction("CREATE_PRODUCT", product.getId());
        
        return product;
    }
    
    @TransactionAttribute(TransactionAttributeType.REQUIRED)
    @RolesAllowed({"admin", "manager"})
    public Product updateProduct(Product product) {
        Product existingProduct = em.find(Product.class, product.getId());
        if (existingProduct == null) {
            throw new EntityNotFoundException("Product not found: " + product.getId());
        }
        
        validateProduct(product);
        
        product.setModifiedDate(new Date());
        product.setModifiedBy(getCurrentUser());
        
        Product updatedProduct = em.merge(product);
        
        auditService.logAction("UPDATE_PRODUCT", product.getId());
        
        return updatedProduct;
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @PermitAll
    public List<Product> findAllProducts() {
        return em.createQuery("SELECT p FROM Product p ORDER BY p.name", Product.class)
                 .getResultList();
    }
    
    @TransactionAttribute(TransactionAttributeType.SUPPORTS)
    @PermitAll
    public Product findProductById(Long id) {
        return em.find(Product.class, id);
    }
    
    private void validateProduct(Product product) {
        if (product.getName() == null || product.getName().trim().isEmpty()) {
            throw new IllegalArgumentException("Product name is required");
        }
        if (product.getPrice() == null || product.getPrice().compareTo(BigDecimal.ZERO) <= 0) {
            throw new IllegalArgumentException("Product price must be greater than zero");
        }
    }
    
    private String getCurrentUser() {
        // 獲取當前用戶邏輯
        return "current_user";
    }
}

// 3. 資料存取層 (JPA + CDI)
@RequestScoped
public class ProductDAO {
    
    @PersistenceContext
    private EntityManager em;
    
    public List<Product> findByCategory(String category) {
        return em.createQuery(
            "SELECT p FROM Product p WHERE p.category = :category", 
            Product.class)
            .setParameter("category", category)
            .getResultList();
    }
    
    public List<Product> findByPriceRange(BigDecimal minPrice, BigDecimal maxPrice) {
        return em.createQuery(
            "SELECT p FROM Product p WHERE p.price BETWEEN :minPrice AND :maxPrice", 
            Product.class)
            .setParameter("minPrice", minPrice)
            .setParameter("maxPrice", maxPrice)
            .getResultList();
    }
}

// 4. 工具服務 (CDI)
@ApplicationScoped
public class CacheService {
    
    private final Map<String, Object> cache = new ConcurrentHashMap<>();
    
    public void put(String key, Object value) {
        cache.put(key, value);
    }
    
    public <T> T get(String key, Class<T> type) {
        Object value = cache.get(key);
        return type.isInstance(value) ? type.cast(value) : null;
    }
    
    public void remove(String key) {
        cache.remove(key);
    }
    
    @Schedule(hour = "2", minute = "0") // 每天凌晨 2 點清除快取
    public void clearCache() {
        cache.clear();
        System.out.println("Cache cleared at: " + new Date());
    }
}
```

## 7. 效能考量

### CDI 效能特點
- **輕量級**: 較少的容器開銷
- **延遲初始化**: 只有在需要時才創建實例
- **範圍管理**: 有效的記憶體管理

### EJB 效能特點
- **池化管理**: 實例池化減少創建開銷
- **交易優化**: 容器級交易管理
- **快取支援**: 內建查詢和實體快取

## 8. 選擇指南

### 使用 CDI 的場景
1. **前端控制器** (JSF Backing Beans)
2. **輕量級服務** (不需要交易管理)
3. **工具類別和快取**
4. **事件驅動架構**
5. **依賴注入和生命週期管理**

### 使用 EJB 的場景
1. **業務邏輯層** (需要交易管理)
2. **安全敏感操作**
3. **遠端服務調用**
4. **定時任務** (@Schedule)
5. **訊息驅動處理** (Message-Driven Beans)

### 混合使用最佳實踐
```
Frontend (JSF + CDI) → Business Layer (EJB) → Data Layer (JPA)
```
```
 前端層 (CDI)            業務層 (EJB)          資料層 (JPA)
┌────────────────┐      ┌─────────────┐      ┌─────────────┐
│ Controller     │      │ Service EJB │      │ Entity/DAO  │
│ (@Named,       │ ---> │ (@Stateless)│ ---> │ (@Entity)   │
│ @RequestScoped)│      │             │      │             │
└────────────────┘      └─────────────┘      └─────────────┘
```
這種架構充分利用了兩種技術的優勢，是企業級應用的推薦模式。
