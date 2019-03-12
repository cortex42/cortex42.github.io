---
layout: default
title: cortex42's pentesting notes
---

{% for category in site.categories %}
  <h2>{{ category[0] }}</h2>
  <ul>
    {% for post in category[1] %}
      <li><a href="{{ post.url}}">{{ post.title }}</a></li>
    {% endfor %}
  </ul>
{% endfor %}

