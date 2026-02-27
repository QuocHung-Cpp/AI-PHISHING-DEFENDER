// ============================================
// CONTENT.JS V2 - OPTIMIZED NO DELAY
// ============================================

(function() {
    'use strict';
    
    const CONFIG = {
        API_URL: 'http://localhost:5000/api/scan',
        CACHE_DURATION: 300000, // 5 phút
        SHOW_SAFE_LINKS: false
    };
    
    // Cache để tránh quét lại URLs đã quét
    const urlCache = new Map();
    
    // ===========================================
    // 1. CACHE SYSTEM - Tăng tốc độ
    // ===========================================
    
    function getCachedResult(url) {
        const cached = urlCache.get(url);
        if (cached && Date.now() - cached.timestamp < CONFIG.CACHE_DURATION) {
            return cached.data;
        }
        return null;
    }
    
    function setCacheResult(url, data) {
        urlCache.set(url, {
            data: data,
            timestamp: Date.now()
        });
    }
    
    // ===========================================
    // 2. OPTIMIZED API CALL - Parallel requests
    // ===========================================
    
    async function scanURL(url) {
        // Check cache trước
        const cached = getCachedResult(url);
        if (cached) {
            console.log('🚀 From cache:', url);
            return cached;
        }
        
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), 10000); // 10s timeout
            
            const response = await fetch(CONFIG.API_URL, {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({url}),
                signal: controller.signal
            });
            
            clearTimeout(timeoutId);
            
            if (response.ok) {
                const data = await response.json();
                setCacheResult(url, data);
                return data;
            }
            return null;
        } catch (error) {
            if (error.name === 'AbortError') {
                console.log('⏱️ Request timeout');
            }
            return null;
        }
    }
    
    // ===========================================
    // 3. MODERN OVERLAY - Instant load
    // ===========================================
    
    function createOverlay(url, result) {
        removeOverlay();
        
        const score = result?.threat_score || 0;
        const verdict = result?.verdict_text || 'Unknown';
        
        let color, emoji, title;
        if (score >= 70) {
            color = '#ef4444';
            emoji = '🚫';
            title = 'DANGEROUS LINK!';
        } else if (score >= 40) {
            color = '#f59e0b';
            emoji = '⚠️';
            title = 'Suspicious Link';
        } else {
            color = '#10b981';
            emoji = '✅';
            title = 'Safe Link';
        }
        
        const overlay = document.createElement('div');
        overlay.id = 'phishing-overlay';
        overlay.innerHTML = `
            <style>
                @keyframes overlayFadeIn {
                    from { opacity: 0; }
                    to { opacity: 1; }
                }
                
                @keyframes slideUp {
                    from {
                        opacity: 0;
                        transform: translate(-50%, -40%) scale(0.9);
                    }
                    to {
                        opacity: 1;
                        transform: translate(-50%, -50%) scale(1);
                    }
                }
                
                #phishing-overlay {
                    position: fixed;
                    top: 0;
                    left: 0;
                    width: 100%;
                    height: 100%;
                    background: rgba(0, 0, 0, 0.75);
                    backdrop-filter: blur(8px);
                    z-index: 2147483647;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
                    animation: overlayFadeIn 0.2s ease-out;
                }
                
                .phishing-dialog {
                    position: fixed;
                    top: 50%;
                    left: 50%;
                    transform: translate(-50%, -50%);
                    background: white;
                    border-radius: 24px;
                    max-width: 560px;
                    width: 90%;
                    max-height: 85vh;
                    overflow: hidden;
                    box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                    animation: slideUp 0.3s cubic-bezier(0.34, 1.56, 0.64, 1);
                }
                
                .phishing-header {
                    background: linear-gradient(135deg, ${color}, ${color}dd);
                    padding: 40px 30px;
                    text-align: center;
                    color: white;
                }
                
                .phishing-icon {
                    font-size: 72px;
                    margin-bottom: 16px;
                    animation: bounceIn 0.6s;
                }
                
                @keyframes bounceIn {
                    0% { transform: scale(0); }
                    50% { transform: scale(1.1); }
                    100% { transform: scale(1); }
                }
                
                .phishing-title {
                    font-size: 28px;
                    font-weight: 800;
                    margin: 0;
                }
                
                .phishing-body {
                    padding: 30px;
                    max-height: 400px;
                    overflow-y: auto;
                }
                
                .url-display {
                    background: #f3f4f6;
                    padding: 16px;
                    border-radius: 12px;
                    word-break: break-all;
                    font-family: 'SF Mono', Monaco, monospace;
                    font-size: 13px;
                    color: #374151;
                    margin-bottom: 24px;
                    border-left: 4px solid ${color};
                }
                
                .score-container {
                    text-align: center;
                    margin: 24px 0;
                }
                
                .score-circle {
                    width: 120px;
                    height: 120px;
                    margin: 0 auto 16px;
                    position: relative;
                    background: linear-gradient(135deg, ${color}20, ${color}10);
                    border-radius: 50%;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                }
                
                .score-value {
                    font-size: 42px;
                    font-weight: 800;
                    color: ${color};
                }
                
                .score-label {
                    color: #6b7280;
                    font-size: 14px;
                    font-weight: 600;
                }
                
                .verdict-badge {
                    display: inline-flex;
                    align-items: center;
                    gap: 8px;
                    background: ${color};
                    color: white;
                    padding: 8px 20px;
                    border-radius: 20px;
                    font-weight: 700;
                    font-size: 16px;
                }
                
                .info-section {
                    background: #f9fafb;
                    padding: 20px;
                    border-radius: 12px;
                    margin: 20px 0;
                }
                
                .info-title {
                    font-weight: 700;
                    color: #1f2937;
                    margin-bottom: 12px;
                    font-size: 15px;
                }
                
                .info-text {
                    color: #4b5563;
                    line-height: 1.6;
                    font-size: 14px;
                }
                
                .recommendation {
                    background: linear-gradient(135deg, #fef3c7, #fde68a);
                    padding: 16px;
                    border-radius: 12px;
                    border-left: 4px solid #f59e0b;
                    margin-top: 16px;
                }
                
                .buttons {
                    display: flex;
                    gap: 12px;
                    margin-top: 24px;
                }
                
                .btn {
                    flex: 1;
                    padding: 16px;
                    border: none;
                    border-radius: 12px;
                    font-size: 16px;
                    font-weight: 700;
                    cursor: pointer;
                    transition: all 0.2s;
                }
                
                .btn:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 16px rgba(0, 0, 0, 0.15);
                }
                
                .btn:active {
                    transform: translateY(0);
                }
                
                .btn-cancel {
                    background: #e5e7eb;
                    color: #374151;
                }
                
                .btn-proceed {
                    background: ${color};
                    color: white;
                }
            </style>
            
            <div class="phishing-dialog">
                <div class="phishing-header">
                    <div class="phishing-icon">${emoji}</div>
                    <h2 class="phishing-title">${title}</h2>
                </div>
                
                <div class="phishing-body">
                    <div class="url-display">${url}</div>
                    
                    <div class="score-container">
                        <div class="score-circle">
                            <div class="score-value">${score}</div>
                        </div>
                        <div class="score-label">THREAT SCORE / 100</div>
                        <div class="verdict-badge">
                            <span>${emoji}</span>
                            <span>${verdict}</span>
                        </div>
                    </div>
                    
                    ${result?.analysis?.ai_analysis ? `
                        <div class="info-section">
                            <div class="info-title">🤖 AI Analysis</div>
                            <div class="info-text">${result.analysis.ai_analysis.reason || 'Analyzing...'}</div>
                        </div>
                        
                        <div class="recommendation">
                            <strong>💡 Recommendation:</strong><br>
                            ${result.analysis.ai_analysis.recommendation || 'Proceed with caution'}
                        </div>
                    ` : ''}
                    
                    <div class="buttons">
                        <button class="btn btn-cancel" id="phishing-cancel">
                            ❌ Cancel
                        </button>
                        <button class="btn btn-proceed" id="phishing-proceed">
                            ${score >= 70 ? '⚠️ Open Anyway' : '✅ Open Link'}
                        </button>
                    </div>
                </div>
            </div>
        `;
        
        document.body.appendChild(overlay);
        
        // Close on Escape
        const escHandler = (e) => {
            if (e.key === 'Escape') {
                removeOverlay();
                document.removeEventListener('keydown', escHandler);
            }
        };
        document.addEventListener('keydown', escHandler);
        
        return new Promise(resolve => {
            document.getElementById('phishing-cancel').onclick = () => {
                removeOverlay();
                resolve(false);
            };
            
            document.getElementById('phishing-proceed').onclick = () => {
                removeOverlay();
                resolve(true);
            };
        });
    }
    
    function removeOverlay() {
        const overlay = document.getElementById('phishing-overlay');
        if (overlay) overlay.remove();
    }
    
    // ===========================================
    // 4. MINI LOADING INDICATOR
    // ===========================================
    
    function showMiniLoading() {
        const loader = document.createElement('div');
        loader.id = 'phishing-mini-loader';
        loader.innerHTML = `
            <style>
                #phishing-mini-loader {
                    position: fixed;
                    top: 20px;
                    right: 20px;
                    background: white;
                    padding: 16px 24px;
                    border-radius: 12px;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.2);
                    z-index: 2147483646;
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    font-family: -apple-system, sans-serif;
                    animation: slideIn 0.3s;
                }
                
                @keyframes slideIn {
                    from { transform: translateX(400px); }
                    to { transform: translateX(0); }
                }
                
                .mini-spinner {
                    width: 20px;
                    height: 20px;
                    border: 3px solid #e5e7eb;
                    border-top-color: #667eea;
                    border-radius: 50%;
                    animation: spin 0.6s linear infinite;
                }
                
                @keyframes spin {
                    to { transform: rotate(360deg); }
                }
            </style>
            <div class="mini-spinner"></div>
            <span style="color: #374151; font-weight: 600;">Scanning link...</span>
        `;
        document.body.appendChild(loader);
    }
    
    function hideMiniLoading() {
        const loader = document.getElementById('phishing-mini-loader');
        if (loader) loader.remove();
    }
    
    // ===========================================
    // 5. OPTIMIZED LINK INTERCEPTOR
    // ===========================================
    
    document.addEventListener('click', async (e) => {
        const link = e.target.closest('a');
        
        // Skip non-links
        if (!link || !link.href) return;
        
        // Skip special links
        if (
            link.href.startsWith('#') ||
            link.href.startsWith('javascript:') ||
            link.href.startsWith('mailto:') ||
            link.href.startsWith('tel:') ||
            link.download
        ) return;
        
        // Skip if Ctrl/Cmd clicked (new tab)
        if (e.ctrlKey || e.metaKey || e.shiftKey) return;
        
        // CHẶN!
        e.preventDefault();
        e.stopPropagation();
        e.stopImmediatePropagation();
        
        const url = link.href;
        
        // Show mini loading
        showMiniLoading();
        
        // Quét (với cache)
        const result = await scanURL(url);
        
        hideMiniLoading();
        
        // Nếu safe và cấu hình không hiện
        if (result && result.threat_score < 40 && !CONFIG.SHOW_SAFE_LINKS) {
            window.location.href = url;
            return;
        }
        
        // Hiện dialog
        const shouldOpen = await createOverlay(url, result);
        
        if (shouldOpen) {
            window.location.href = url;
        }
        
    }, true); // Capture phase
    
    // ===========================================
    // 6. INITIALIZATION
    // ===========================================
    
    console.log('%c🛡️ AI Phishing Defender V2', 'font-size: 16px; font-weight: bold; color: #667eea;');
    console.log('%cProtecting you with optimized performance!', 'color: #10b981;');
    
    // Preload cache cho common domains
    const commonSafeDomains = [
        'google.com', 'youtube.com', 'facebook.com',
        'twitter.com', 'github.com', 'stackoverflow.com'
    ];
    
    // Mark common domains as safe (skip scanning)
    commonSafeDomains.forEach(domain => {
        urlCache.set(`https://${domain}`, {
            data: {success: true, threat_score: 0, verdict_text: 'Safe'},
            timestamp: Date.now()
        });
    });
    
})();