// 全局JavaScript函数

// 设置当前年份
function setCurrentYear() {
    const yearElements = document.querySelectorAll('.container footer p');
    const currentYear = new Date().getFullYear();
    
    yearElements.forEach(element => {
        element.innerHTML = element.innerHTML.replace('{{ current_year }}', currentYear);
    });
}

// 页面加载完成后执行
document.addEventListener('DOMContentLoaded', function() {
    setCurrentYear();
    
    // 可以添加更多页面加载后的初始化代码
});