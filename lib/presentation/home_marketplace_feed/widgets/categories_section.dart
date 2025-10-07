import 'package:flutter/material.dart';
import 'package:sizer/sizer.dart';

class CategoriesSection extends StatelessWidget {
  final List<Map<String, Object>> categories;
  final String selected;
  final void Function(String) onSelect;

  const CategoriesSection({
    Key? key,
    required this.categories,
    required this.selected,
    required this.onSelect,
  }) : super(key: key);

  @override
  Widget build(BuildContext context) {
    return Container(
      height: 11.h,
      margin: EdgeInsets.symmetric(vertical: 1.h),
      child: ListView.builder(
        scrollDirection: Axis.horizontal,
        padding: EdgeInsets.symmetric(horizontal: 4.w),
        itemCount: categories.length,
        itemBuilder: (_, index) {
          final cat = categories[index];
          final isSelected = cat['name'] == selected;
          final isAllCategory = cat['name'] == 'All';
          
          return GestureDetector(
            onTap: () => onSelect(cat['name'] as String),
            child: Container(
              margin: EdgeInsets.only(right: 3.w),
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  AnimatedContainer(
                    duration: Duration(milliseconds: 200),
                    width: 56,
                    height: 56,
                    padding: EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: isSelected ? Color(0xFF2563EB) : Colors.white,
                      shape: BoxShape.circle,
                      border: Border.all(
                        color: isSelected
                            ? Color(0xFF2563EB)
                            : Colors.grey[300]!,
                        width: 2,
                      ),
                      boxShadow: isSelected
                          ? [
                              BoxShadow(
                                color: Color(0xFF2563EB).withOpacity(0.3),
                                blurRadius: 10,
                                offset: Offset(0, 3),
                              ),
                            ]
                          : [],
                    ),
                    child: _buildCategoryIcon(cat, isSelected, isAllCategory),
                  ),
                  SizedBox(height: 6),
                  Text(
                    cat['name'] as String,
                    style: TextStyle(
                      fontSize: 11,
                      color:
                          isSelected ? Color(0xFF2563EB) : Colors.grey[700],
                      fontWeight:
                          isSelected ? FontWeight.bold : FontWeight.normal,
                    ),
                  ),
                ],
              ),
            ),
          );
        },
      ),
    );
  }

  Widget _buildCategoryIcon(Map<String, Object> cat, bool isSelected, bool isAllCategory) {
    // For "ALL" category, always use the icon (not the image) for better contrast
    if (isAllCategory) {
      return Icon(
        cat['icon'] as IconData,
        color: isSelected ? Colors.white : Color(0xFF2563EB),
        size: 26,
      );
    }

    // For other categories, try to load image first, fallback to icon
    if (cat['image'] != null && (cat['image'] as String).isNotEmpty) {
      return ClipRRect(
        borderRadius: BorderRadius.circular(8),
        child: Image.network(
          cat['image'] as String,
          width: 32,
          height: 32,
          fit: BoxFit.contain,
          loadingBuilder: (context, child, loadingProgress) {
            if (loadingProgress == null) return child;
            return Center(
              child: CircularProgressIndicator(
                strokeWidth: 2,
                value: loadingProgress.expectedTotalBytes != null
                    ? loadingProgress.cumulativeBytesLoaded /
                        loadingProgress.expectedTotalBytes!
                    : null,
              ),
            );
          },
          errorBuilder: (context, error, stackTrace) {
            return Icon(
              cat['icon'] as IconData,
              color: isSelected ? Colors.white : Color(0xFF2563EB),
              size: 26,
            );
          },
        ),
      );
    }

    // Fallback to icon if no image
    return Icon(
      cat['icon'] as IconData,
      color: isSelected ? Colors.white : Color(0xFF2563EB),
      size: 26,
    );
  }
}